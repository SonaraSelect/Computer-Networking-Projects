import socket
import struct
import threading
import time  
from enum import Enum, auto
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload

    def encode(self):
        # Encode the packet header and payload into bytes
        header = struct.pack("!IIIH", self.seq, self.ack, self.flags, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIIH")
        seq, ack, flags, payload_len = struct.unpack("!IIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, payload)


class State(Enum):
    LISTEN      = auto()
    SYN_SENT    = auto()
    SYN_RCVD    = auto()
    ESTABLISHED = auto()
    FIN_SENT    = auto()
    CLOSE_WAIT  = auto()
    TIME_WAIT   = auto()
    LAST_ACK    = auto()
    CLOSED      = auto()


class TransportSocket:
    def __init__(self):
        self.sock_fd = None

        # Locks and condition
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        self.window = {
            "last_ack": 0,            # The next seq we expect from peer (used for receiving data)
            "next_seq_expected": 0,   # The highest ack we've received for *our* transmitted data
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # How many bytes are in recv_buf
            "next_seq_to_send": 0,    # The sequence number for the next packet we send
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None

        # my additions -----------
        self.state = State.LISTEN
        self.close_timer = None
        self.data_buffer = []

        self.est_rtt = DEFAULT_TIMEOUT           # Initial Estimated RTT
        self.alpha = 0.5                         # Alpha value between 0 and 1
        self.RTT = DEFAULT_TIMEOUT               # Initial retransmission timeout
        self.packet_send_times = {}              # Tracker of when each packet was sent


    def add_to_buffer(self, packet):
        """
        Add a packet to the end of the data_buffer. Will automatically sort and ignore repeats
        """
        match(len(self.data_buffer)):
            case 0:
                self.data_buffer.append(packet)

            case 1:
                if packet.seq < self.data_buffer[0].seq:
                    self.data_buffer.insert(0,packet)
                else:
                    self.data_buffer.append(packet)
                
            case _:
                for i, buffered_packet in enumerate(self.data_buffer):
                    if i+1 < len(self.data_buffer):
                        # If packet seq fits between this buffered packet and the next one
                        if buffered_packet.seq < packet.seq and packet.seq < self.data_buffer[i+1].seq:
                            self.data_buffer.insert(i+1, packet)
                            return
                # If packet seq number greater than all buffered packets
                if(self.data_buffer[len(self.data_buffer) - 1].seq < packet.seq):
                    self.data_buffer.append(packet)


    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # Bind to any available local port
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
        else:
            print("Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can periodically check `self.dying`
        self.sock_fd.settimeout(1.0)

        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket and stop the backend thread.
        """
        print(f" {self.state} CLOSED has been run")
        # self.state = State.CLOSED # <------------------------------------
        # if not self.state == State.CLOSED:
        #     self.send_fin_packet()

        if self.state == State.ESTABLISHED or self.state == State.SYN_RCVD:
            print(f"==> {self.state} ran close() transitioning to FIN_SENT")
            # self.state = State.FIN_SET
            self.send_fin_packet()
        else:
            print(f"==> {self.state} ran close() transitioning to LAST_ACK")
            self.state = State.LAST_ACK

        # Wait until CLOSED or timeout
        with self.wait_cond:
            self.wait_cond.wait_for(lambda: self.state == State.CLOSED, timeout=1)


        self.death_lock.acquire()
        try:
            self.dying = True
        finally:
            self.death_lock.release()

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            print("Error: Null socket")
            return EXIT_ERROR

        print("BACKEND FULLY CLOSED")
        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data reliably to the peer (stop-and-wait style).
        """
        if not self.conn:
            raise ValueError("Connection not established.")
        with self.send_lock:

            # Send SYN if we are just now initiating the connection
            if self.state == State.LISTEN:
                self.send_syn_packet()
            
            self.send_segment(data)

            # Finished sending. Send FIN
            # self.send_fin_packet()

    # def send_syn_packet(self):
    #     seq_no = self.window["next_seq_to_send"]
    #     ack_no = self.window["last_ack"]
    #     payload = b''

    #     syn = Packet(
    #         seq= seq_no,
    #         ack=self.window["last_ack"],
    #         flags=SYN_FLAG,
    #         payload=payload
    #         )
        
    #     self.state = State.SYN_SENT

    #     print(f"BEFORE next seq {self.window["next_seq_to_send"]}")

    
    #     while True:
            

    #         print(f"==> LISTEN Sending SYN segment {seq_no}, size {len(payload)} transitioning to SYN_SENT")
    #         self.sock_fd.sendto(syn.encode(), self.conn)
    #         if(self.wait_for_ack(seq_no + len(payload))):
    #             print(f"SYN+ACK segment {seq_no} acknowledged")
    #             self.window["next_seq_to_send"] += len(payload)
    #             print(f"AFTER next seq {self.window["next_seq_to_send"]}")
    #             break

    def send_syn_packet(self):
        seq_no = self.window["next_seq_to_send"]
        payload = b''  # Or include some handshake payload if needed

        syn = Packet(
            seq=seq_no,
            ack=self.window["last_ack"],
            flags=SYN_FLAG,
            payload=payload
        )
        
        self.state = State.SYN_SENT
        
        while self.state != State.ESTABLISHED:
            self.sock_fd.sendto(syn.encode(), self.conn)
            # Wait a short time before resending, or wait for state change using a condition variable
            with self.wait_cond:
                self.wait_cond.wait_for(lambda: self.state == State.ESTABLISHED, timeout=DEFAULT_TIMEOUT)
        print(f"==> LISTEN Sending SYN segment {seq_no}, size {len(payload)} transitioning to SYN_SENT")

    def send_fin_packet(self):
        seq_no = self.window["next_seq_to_send"]
        payload = b''

        fin = Packet(
            seq=seq_no,
            ack=self.window["last_ack"],
            flags=FIN_FLAG,
            payload=payload
        )

        self.state = State.FIN_SENT
        
        while self.state != State.TIME_WAIT: # or self.state != State.CLOSE_WAIT:
            self.sock_fd.sendto(fin.encode(), self.conn)
            with self.wait_cond:
                self.wait_cond.wait_for(lambda: self.state == State.TIME_WAIT, timeout=DEFAULT_TIMEOUT)
        print(f"==> {self.state} Sending FIN segment {seq_no}, size {len(payload)} transitioning to FIN_SENT")            
            


    def recv(self, buf, length, flags):
        """
        Retrieve received data from the buffer, with optional blocking behavior.

        :param buf: Buffer to store received data (list of bytes or bytearray).
        :param length: Maximum length of data to read
        :param flags: ReadMode flag to control blocking behavior
        :return: Number of bytes read
        """
        read_len = 0

        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        # If blocking read, wait until there's data in buffer
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    self.wait_cond.wait()

        self.recv_lock.acquire()
        try:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]

                    # Remove data from the buffer
                    if read_len < self.window["recv_len"]:
                        self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                        self.window["recv_len"] -= read_len
                    else:
                        self.window["recv_buf"] = b""
                        self.window["recv_len"] = 0
            else:
                print("ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    def send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and reliably wait for each ACK
        """
        offset = 0
        total_len = len(data)

        
        if self.state == State.ESTABLISHED:

            # While there's data left to send
            while offset < total_len:
                payload_len = min(MSS, total_len - offset)

                # Current sequence number
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset : offset + payload_len]

                # Create a packet
                segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, payload=chunk)

                # We expect an ACK for seq_no + payload_len
                ack_goal = seq_no + payload_len

                # Record time packet is sent
                self.packet_send_times[ack_goal] = time.time()

                while True:
                    print(f"Sending segment (seq={seq_no}, len={payload_len})")
                    self.sock_fd.sendto(segment.encode(), self.conn)

                    if self.wait_for_ack(ack_goal):
                        print(f"Segment {seq_no} acknowledged.")
                        # Advance our next_seq_to_send
                        self.window["next_seq_to_send"] += payload_len
                        break
                    else:
                        print("Timeout: Retransmitting segment.")

                offset += payload_len


    def wait_for_ack(self, ack_goal):
        """
        Wait for 'next_seq_expected' to reach or exceed 'ack_goal' within DEFAULT_TIMEOUT.
        Return True if ack arrived in time; False on timeout.
        """
        with self.recv_lock:
            start = time.time()
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = DEFAULT_TIMEOUT - elapsed
                if remaining <= 0:
                    return False
# 
                self.wait_cond.wait(timeout=remaining)

            # ACK has been received, now calculate RTT
            send_time = self.packet_send_times.get(ack_goal, None)
            if send_time is not None:
                sample_rtt = time.time() - send_time
                # Remove it from the dict so we don't reuse it
                del self.packet_send_times[ack_goal]

                # Update moothed_rtt with EWMA:
                # est_rtt = alpha * est_rtt + (1 - alpha) * sample_rtt
                self.est_rtt = self.alpha * self.est_rtt + (1.0 - self.alpha) * sample_rtt

                # Optionally set your timeout as some multiple of est_rtt (e.g., 2 * est_rtt)
                self.timeout = 2 * self.est_rtt
                print(f"Updated RTT: sample={sample_rtt:.4f}, est_rtt={self.est_rtt:.4f}, timeout={self.timeout:.4f}")
            return True
        
    def send_ack(self, packet, flags, addr):
        ack_val = packet.seq + len(packet.payload)
        ack_packet = Packet(seq=packet.ack, ack=ack_val, flags=flags)
        self.sock_fd.sendto(ack_packet.encode(), addr)
        # Update last_ack
        self.window["last_ack"] = ack_val

    def backend(self):
        """
        Backend loop to handle receiving data and sending acknowledgments.
        All incoming packets are read in this thread only, to avoid concurrency conflicts.
        """
        while not self.dying:
            try:

                # Handle death timers
                if self.state == State.TIME_WAIT or self.state == State.CLOSE_WAIT:
                    if not self.close_timer:
                        self.close_timer = time.time()

                    if time.time() - self.close_timer > 2 * self.est_rtt:
                        self.state = State.CLOSED
                        print(f"{self.state} Now closing...")
                        # self.close()


                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr

                match(self.state):
                    case(State.LISTEN):
                        # If it's a SYN packet, send SYN+ACK
                        if packet.flags & SYN_FLAG != 0:
                            with self.recv_lock:
                                print("==> Received SYN, transitioning to SYN_RCVD")
                                
                                # self.window["next_seq_to_send"] += packet.ack
                                # self.window["last_ack"] = packet.seq

                                # response = Packet(
                                #     self.window["next_seq_to_send"],
                                #     self.window["last_ack"]
                                # )
                                
                                self.send_ack(packet, SYN_FLAG+ACK_FLAG, addr)

                                self.state = State.SYN_RCVD
                                self.wait_cond.notify_all()
                                continue
                                
                    
                    case(State.SYN_SENT):
                        # If we get a SYN+ACK
                        if packet.flags & (SYN_FLAG + ACK_FLAG) != 0:
                            with self.recv_lock:
                                # Send back an ack
                                print("==> SYN_SENT Received SYN+ACK transitioning to ESTABLISHED")
                                self.send_ack(packet, ACK_FLAG, addr)
                                
                                self.state = State.ESTABLISHED
                                self.wait_cond.notify_all()
                                continue

                        # If we get just a SYN
                        elif packet.flags & SYN_FLAG != 0:
                            with self.recv_lock:
                                # send syn ack
                                print("==> SYN Received SYN, sending SYN+ACK. Trans. to SYN_RCVD")
                                self.send_ack(packet, SYN_FLAG+ACK_FLAG, addr)

                                self.state = State.SYN_RCVD
                                self.wait_cond.notify_all()
                                continue


                    case(State.SYN_RCVD):
                        if packet.flags & ACK_FLAG != 0:
                            with self.recv_lock:
                                print("==> SYN_RCVD Received ACK, trans. to ESTABLISHED")

                                self.state = State.ESTABLISHED
                                self.wait_cond.notify_all()
                                continue

                    case(State.ESTABLISHED):

                        # If it's a FIN packet, transition to CLOSE_WAIT
                        if packet.flags & FIN_FLAG != 0:
                            with self.recv_lock:
                                print("==> ESTABLISHED received FIN transitioning to CLOSE_WAIT")
                                self.send_ack(packet, ACK_FLAG, addr)
                                
                                self.state = State.CLOSE_WAIT
                                self.wait_cond.notify_all()
                                continue


                        # If it's an ACK packet, update our sending side
                        if (packet.flags & ACK_FLAG) != 0:
                            with self.recv_lock:
                                if packet.ack > self.window["next_seq_expected"]:
                                    self.window["next_seq_expected"] = packet.ack
                                self.wait_cond.notify_all()
                            continue

                        # Otherwise, assume it is a data packet
                        # Check if the sequence matches our 'last_ack' (in-order data)
                        if packet.seq == self.window["last_ack"]:
                            with self.recv_lock:
                                # Append payload to our receive buffer
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)

                            with self.wait_cond:
                                self.wait_cond.notify_all()

                            print(f"Received segment {packet.seq} with {len(packet.payload)} bytes.")

                            # Send back an acknowledgment & Update last ACK
                            self.send_ack(packet, ACK_FLAG, addr)

                        else:
                            # todo For a real TCP, we need to send duplicate ACK or ignore out-of-order data
                            print(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")

                            # check if in buffer
                            # if not in buffer, add to buffer
                            
                            # if correct order, still add to buffer
                            # buffer ordered by seq num

                    case(State.FIN_SENT):
                        # If we get an ACK packet, transition to TIME_WAIT
                        if packet.flags & ACK_FLAG:
                            with self.recv_lock:
                                print(f"==> {self.state} FIN_SENT Received ACK, transitioning to TIME_WAIT")

                                self.state = State.TIME_WAIT
                                self.wait_cond.notify_all()
                                continue
                        # If we get a FIN packet, send ack and transition to TIME_WAIT
                        if packet.flags & FIN_FLAG != 0:
                            with self.recv_lock:
                                print(f"==> {self.state} FIN_SENT Received FIN_FLAG, send ACK then transitioning to TIME_WAIT")
                                self.send_ack(packet, ACK_FLAG, addr)

                                self.state = State.TIME_WAIT
                                self.wait_cond.notify_all()
                                continue

                        if packet.flags & 0x00 != 0:
                            with self.recv_lock:
                                print("======> FIN_SENT Received data packet. Transitioning to ESTABLISHED")


                                if packet.seq == self.window["last_ack"]:
                                    with self.recv_lock:
                                        # Append payload to our receive buffer
                                        self.window["recv_buf"] += packet.payload
                                        self.window["recv_len"] += len(packet.payload)

                                    with self.wait_cond:
                                        self.wait_cond.notify_all()

                                    print(f"Received segment {packet.seq} with {len(packet.payload)} bytes.")

                                # Send back an acknowledgment & Update last ACK
                                self.send_ack(packet, ACK_FLAG, addr)


                                self.state = State.ESTABLISHED
                                self.wait_cond.notify_all()
                                continue

                    case(State.TIME_WAIT):
                        # todo make this state also go to CLOSED automatically
                        # If we get a FIN packet, send ACK and transition to CLOSED
                        if packet.flags & FIN_FLAG != 0:
                            with self.recv_lock:
                                # print("==> FIN_SENT Received FIN_FLAG, send ACK then transitioning to TIME_WAIT")
                                # self.send_ack(packet, ACK_FLAG, addr)

                                # self.state = State.CLOSED
                                # self.wait_cond.notify_all()
                                # continue

                                if not self.close_timer:
                                    self.close_timer = time.time()
                                elif time.time() - self.close_timer > 0.05:
                                    with self.recv_lock:
                                        self.state = State.CLOSED
                                        self.wait_cond.notify_all()
                                                    
                    case(State.CLOSE_WAIT):
                        # todo make automatically go to CLOSED
                        # If it's an ACK packet, update our sending side
                        if (packet.flags & ACK_FLAG) != 0:
                            with self.recv_lock:
                                if packet.ack > self.window["next_seq_expected"]:
                                    self.window["next_seq_expected"] = packet.ack
                                
                                self.wait_cond.notify_all()
                                continue

                    case(State.LAST_ACK):
                        if packet.flags * ACK_FLAG !=0:
                            with self.recv_lock:
                                print("==> LACT_ACK Received ACK. transitioning to CLOSED")
                                
                                # self.close() # <------- do this? <----------

                                self.state = State.CLOSED
                                self.wait_cond.notify_all()
                                continue

                    case(State.CLOSED):
                        print("==> CLOSED Connection has closed.")
                        continue #todo maybe make this break

                    

            except socket.timeout:
                continue
        
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")

