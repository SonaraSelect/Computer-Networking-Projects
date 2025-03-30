import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1
DATA_SEQ = "!IIIHI"

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b"", window_size=0):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload
        self.window_size = window_size

    def encode(self):
        # Encode the packet header and payload into bytes
        header = struct.pack(DATA_SEQ, self.seq, self.ack, self.flags, len(self.payload), self.window_size)
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize(DATA_SEQ)
        seq, ack, flags, payload_len, window_size = struct.unpack(DATA_SEQ, data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, payload, window_size)


class TransportSocket:
    def __init__(self):
        self.sock_fd = None

        # Locks and condition
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.death_cond = threading.Condition(self.death_lock)
        self.dying = False
        self.thread = None

        self.window = {
            "last_ack": 0,            # The next seq we expect from peer (used for receiving data), aka last ack we sent
            "next_seq_expected": 0,   # The highest ack we've received for *our* transmitted data, aka last ack we received
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # How many bytes are in recv_buf
            "next_seq_to_send": 0,    # The sequence number for the next packet we send
            "status": "LISTEN",        # Status in the FSM: in enum ("LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_SENT", "CLOSE_WAIT", "TIME_WAIT", "LAST_ACK", "CLOSED")
            "our_window": MAX_NETWORK_BUFFER,
            "peer_window": MAX_NETWORK_BUFFER
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None

        self.timeout = 3
        self.closing_time = None
        

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

        self.window["our_window"] = self.get_window()

        # Start the backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket and stop the backend thread.
        """

        # We are now done sending data
        # We send a FIN to signify this
        fin_packet = Packet(seq = self.window["next_seq_to_send"], ack = self.window["last_ack"], flags = FIN_FLAG, window_size=self.get_window())
        print(fin_packet.window_size)
        # If the peer is waiting on us to finish, go into LAST_ACK instead
        if self.window["status"] == "ESTABLISHED" or self.window["status"] == "SYN_RCVD":
            self.window["status"] = "FIN_SENT" 
        else:
            self.window["status"] = "LAST_ACK" 

        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        print(f"[FIN] (seq={fin_packet.seq}, ack={fin_packet.ack})")
        self.window["next_seq_to_send"] += len(fin_packet.payload)

        with self.death_cond:
            if self.dying == False:
                self.death_cond.wait()

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            print("Error: Null socket")
            return EXIT_ERROR
        print("Closed Successfully!")
        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data reliably to the peer (stop-and-wait style).
        """
        if not self.conn:
            raise ValueError("Connection not established.")
        with self.send_lock:
            self.send_segment(data)

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
    
    def send_syn(self):
        """
        Send a syn to initiate TCP handshake
        """
        syn_packet = Packet(seq=self.window["next_seq_to_send"], ack = self.window["last_ack"], flags=SYN_FLAG, window_size=self.get_window())
        self.window["status"] = "SYN_SENT"
        retries = 0
        while retries < 5:
            print(f"[SYN] sent (seq={syn_packet.seq}, ack={syn_packet.ack})")
            self.sock_fd.sendto(syn_packet.encode(), self.conn)
            
            if self.wait_for_ack(syn_packet.seq):
                break
            else:
                retries += 1
                print(f"[TIMEOUT] Retransmitting syn. Retries: {retries}")


    def send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and reliably wait for each ACK
        """
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            
            # Check if syn has been sent
            if self.window["status"] == "LISTEN":
                self.send_syn()

            
            payload_len = min(MSS, total_len - offset, MAX_NETWORK_BUFFER-1)

            # Current sequence number
            seq_no = self.window["next_seq_to_send"]
            chunk = data[offset : offset + payload_len]

            # Create a packet, always have an ack in TCP after initial SYN
            segment = Packet(seq=seq_no, ack=self.window["last_ack"], payload=chunk, window_size=self.get_window())

            # We expect an ACK for seq_no + payload_len
            ack_goal = seq_no + payload_len

            if payload_len > self.window["peer_window"]:
                self.window["peer_window"] += 10

            retries = 0
            while True:
                 
                 
                print(f"[SENT] packet (seq={seq_no}, ack={self.window["last_ack"]}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)
                time.sleep(0.1)
                if self.wait_for_ack(ack_goal):
                    # Advance our next_seq_to_send
                    self.window["next_seq_to_send"] += payload_len
                    break
                else:
                    retries += 1
                    print(f"[TIMEOUT]: Retransmitting segment. Retries: {retries}")

            offset += payload_len

        


    def wait_for_ack(self, ack_goal):
        """
        Wait for 'next_seq_expected' to reach or exceed 'ack_goal' within DEFAULT_TIMEOUT.
        Return True if ack arrived in time; False on timeout.
        """
        with self.recv_lock:
            start = time.time()
            while self.window["status"] != "ESTABLISHED" :
                elapsed = time.time() - start
                remaining = DEFAULT_TIMEOUT - elapsed
                if remaining <= 0 and self.window["status"]:   
                    return False

                self.wait_cond.wait(timeout=remaining)

            return True
            

    def backend(self):
        """
        Backend loop to handle receiving data and sending acknowledgments.
        All incoming packets are read in this thread only, to avoid concurrency conflicts.
        """
        while self.window["status"] != "CLOSED":
            try:
                if self.window["status"] == "TIME_WAIT" or self.window["status"] == "CLOSE_WAIT":
                # Initiate shutdown clock if not already done so
                    if not self.closing_time:
                        self.closing_time = time.time()

                    # Once clock runs out shut ourselves down
                    if time.time() - self.closing_time > 2*self.timeout:
                        self.window["status"] = "CLOSED"
                        print("Backend Closing...")
                        continue

                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)
                self.window["peer_window"] = packet.window_size
                
                # Reset our time if we get a new packet
                

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr
                    
                # Check if a connection is established
                match self.window["status"]:
                    case "LISTEN":
                        # If it's a SYN packet, go to SYN_RCVD and send SYN_ACK
                        if packet.flags & SYN_FLAG !=0:
                            print(f"[SYN] received (seq={packet.seq}, ack={packet.ack})")
                            self.window["next_seq_to_send"] = packet.seq 
                            self.window["status"] = "SYN_RCVD"
                            # Update last ack we received
                            self.update_ack(packet)
                            
                            self.ack_packet(packet, SYN_FLAG + ACK_FLAG, addr)
                            
                            continue
                        
                    case "SYN_SENT":
                        # Upon SYN_ACK receipt 
                        if packet.flags & (SYN_FLAG + ACK_FLAG) != 0:
                            print(f"[SYN-ACK] received (seq={packet.seq}, ack={packet.ack})")
                            self.update_ack(packet)
                            self.window["last_ack"] += len(packet.payload)

                            ack_packet = Packet(seq = self.window["next_seq_to_send"], ack = self.window["last_ack"], flags = ACK_FLAG, window_size=self.get_window())
                            self.sock_fd.sendto(ack_packet.encode(), addr)

                            print(f"[ACKING] (seq={ack_packet.seq}, ack={self.window["last_ack"]})")
                            print("[ESTABLISHED] Handshake complete!")
                            self.window["status"] = "ESTABLISHED"
                            continue
                            
                            
                    case "SYN_RCVD":
                        # Upon ACK receipt
                        if packet.flags & ACK_FLAG !=0:
                            print("[ESTABLISHED] Handshake complete!")
                            self.window["status"] = "ESTABLISHED"
                            self.update_ack(packet)
                            continue
                            
                    case "ESTABLISHED":
                        # If its a FIN packet, ACK it, go into CLOSE_WAIT to finish sending data
                        if packet.flags & FIN_FLAG != 0:
                            self.ack_packet(packet, FIN_FLAG+ACK_FLAG, addr)
                            
                            self.window["status"] = "CLOSE_WAIT"
                            print("Entering CLOSE_WAIT")

                            continue

                        
                        # If it's an ACK packet, update our sending side
                        if (packet.flags & ACK_FLAG) != 0:
                            print(f"[ACKED] (seq={packet.seq}, ack={packet.ack})")
                            self.update_ack(packet)
                            continue

                        # Otherwise, assume it is a data packet
                        # Check for an established connection and if the sequence matches our 'last_ack' (in-order data)
                        
                        if packet.seq == self.window["last_ack"]:
                            with self.recv_lock:
                                # Append payload to our receive buffer
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)

                            with self.wait_cond:
                                self.wait_cond.notify_all()
                            
                            print(f"[RCVD] (seq={packet.seq}, ack={packet.ack}, len={len(packet.payload)})")

                            # Log the received data
                            self.ack_packet(packet, ACK_FLAG, addr)
                            
                            continue

                        else:
                            # For a real TCP, we need to send duplicate ACK or ignore out-of-order data
                            print(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")
                            continue
                    
                    case "FIN_SENT":
                        # If FIN-ACK packet, go into TIME_WAIT
                        if packet.flags & (ACK_FLAG + FIN_FLAG) !=0:
                            print(f"[FIN-ACKED] (seq={packet.seq}, ack={packet.ack})")
                            print("Entering TIME_WAIT")

                            self.window["status"] = "TIME_WAIT"
                            continue

                        # If FIN packet, send an ack and go into TIME_WAIT
                        if packet.flags & FIN_FLAG !=0:
                            self.ack_packet(packet, FIN_FLAG+ACK_FLAG, addr)

                            self.window["status"] = "TIME_WAIT"
                            print("Entering TIME_WAIT")
                            continue

                    case "CLOSE_WAIT":
                        # The only thing we should be receiving in CLOSE_WAIT are acks for our packets
                        if packet.flags & ACK_FLAG != 0:
                            print(f"[ACKED] (seq={packet.seq}, ack={packet.ack})")
                            self.update_ack(packet)
                            # Update the closing time
                            self.closing_time = time.time()
                            continue
                    
                    case "TIME_WAIT":
                        # If we get a packet during TIME_WAIT we ack it
                        print(f"[RCVD] (seq={packet.seq}, ack={packet.ack}, len={len(packet.payload)})")
                        flags = ACK_FLAG
                        if packet.flags & FIN_FLAG:
                            flags += FIN_FLAG
                        
                        self.ack_packet(packet, flags, addr)
                        # Update the closing time
                        self.closing_time = time.time()
                        continue
                        
                    case "LAST_ACK":
                        # If received our ack for our last segment close ourself.
                        if packet.flags & (FIN_FLAG + ACK_FLAG) != 0:
                            print(f"[FIN-ACKED] (seq={packet.seq}, ack={packet.ack})")
                            print("[CLOSING]")
                            self.window["status"] = "CLOSED"
                            break
                            
                    
                    case "CLOSED":
                        # If we are closed, we must end the backend
                        break
                        
                    case _:
                        print(f"Error in status {self.window["status"]}")
                    
                    
            except socket.timeout:
                continue
        
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")
                    break

        with self.death_lock:
            self.dying = True
            self.death_cond.notify_all()


    def update_ack(self, packet):
        """
        Helper method to quickly update the last ack received and update the send side
        """
        with self.recv_lock:
            if packet.ack > self.window["next_seq_expected"]:
                self.window["next_seq_expected"] = packet.ack
            self.wait_cond.notify_all()
    
    def ack_packet(self, packet, flags, addr):
        # Send back an acknowledgment
        ack_val = packet.seq + len(packet.payload)
        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=ack_val, flags=flags, window_size=self.get_window())
        self.sock_fd.sendto(ack_packet.encode(), addr)
        # Update last_ack
        self.window["last_ack"] = ack_val

        kind = ""
        if flags & FIN_FLAG !=0: 
            kind = "ACKING FIN"

        elif flags & SYN_FLAG != 0:
            kind = "ACKING SYN"
        else:
            kind = "ACKING"
            
        print(f"[{kind}] (seq={ack_packet.seq}, ack={self.window["last_ack"]})")


    def get_window(self):
        window = MAX_NETWORK_BUFFER - self.window["recv_len"]
        return 0 if window<0 else window
