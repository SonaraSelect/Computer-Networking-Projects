import socket
import struct
import threading
import time  
from enum import Enum, auto
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER, WINDOW_INITIAL_WINDOW_SIZE, WINDOW_INITIAL_SSTHRESH

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
    def __init__(self, seq=0, ack=0, flags=0, window=0, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window  # New 16-bit Advertised Window field
        self.payload = payload

    def encode(self):
        # Update the struct format string to include window (H) and payload length (H)
        header = struct.pack("!IIIHH", self.seq, self.ack, self.flags, self.window, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        # Calculate the new header size with the advertised window field included
        header_size = struct.calcsize("!IIIHH")
        seq, ack, flags, window, payload_len = struct.unpack("!IIIHH", data[:header_size])
        payload = data[header_size: header_size + payload_len]
        return Packet(seq, ack, flags, window, payload)



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

class TCP_State(Enum):
    SLOW_START = auto()
    CONG_AVOID = auto()
    FAST_RECOV = auto()

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
            # my additions -----
            "send_buf": [],           # Send data buffer
            "sendQ" : [],
            "sws": 3,
            "adv_window": 1,
            }
        self.sock_type = None
        self.conn = None
        self.my_port = None

        # my additions -----------
        self.state = State.LISTEN
        self.tcp_state = TCP_State.SLOW_START
        self.dup_ack_cnt = 0
        self.ssthresh = WINDOW_INITIAL_SSTHRESH
        self.cwnd = WINDOW_INITIAL_WINDOW_SIZE
        self.close_timer = None
        self.output_buffer = []
        self.data_buffer = []
        self.ack_timer = -1                      # Timer used to retransmit special ACKs. Will be -1 when not in use
        self.last_ack_packet = None              # Special ACK packet to be retransmitted

        self.est_rtt = DEFAULT_TIMEOUT           # Initial Estimated RTT
        self.alpha = 0.5                         # Alpha value between 0 and 1
        self.RTT = DEFAULT_TIMEOUT               # Initial retransmission timeout
        self.packet_send_times = {}              # Tracker of when each packet was sent


    def add_to_buffer(self, packet):
        """
        Add a packet to the data_buffer, ensuring the buffer remains sorted by packet sequence number.
        If a packet with the same sequence number already exists, it is ignored.
        """
        # If buffer is at max capacity, do not append
        if len(self.data_buffer) >= MAX_NETWORK_BUFFER:
            print("==> Tried to add recvd packet to full buffer!")
            return

        # If the buffer is empty, simply append.
        if not self.data_buffer:
            self.data_buffer.append(packet)
            return

        # Check for duplicates.
        for p in self.data_buffer:
            if p.seq == packet.seq:
                # Duplicate packet; ignore it.
                return

        # If the new packet's sequence number is less than the first element, insert at beginning.
        if packet.seq < self.data_buffer[0].seq:
            self.data_buffer.insert(0, packet)
            return

        # Otherwise, find the proper insertion index.
        inserted = False
        for i in range(len(self.data_buffer) - 1):
            # If packet.seq fits between data_buffer[i] and data_buffer[i+1]
            if self.data_buffer[i].seq < packet.seq < self.data_buffer[i+1].seq:
                self.data_buffer.insert(i + 1, packet)
                inserted = True
                break

        # If not inserted, then packet.seq is greater than all in the buffer; append it.
        if not inserted:
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

            # todo check for data in send buffer

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
    
    def tcp_handle_timeout(self):
        self.ssthresh = self.cwnd / 2
        self.cwnd = 1
        self.dup_ack_cnt = 0

        # todo retransmit missing segment

        self.tcp_state = TCP_State.SLOW_START

        print(f"==>Timeout: {self.tcp_state} cwnd={int(self.cwnd * MSS)} ssthresh={int(self.ssthresh * MSS)}")

    def tcp_handle_dup_ack(self):
        if self.tcp_state == TCP_State.FAST_RECOV:
            self.cwnd += 1
            #todo transmit new segments as allowed

        # If in SLOW_START or CONG_AVOID
        else:
            self.dup_ack_cnt += 1

            if(self.dup_ack_cnt == 3):
                self.ssthresh = self.cwnd / 2
                self.cwnd = self.ssthresh + 3
                # todo retransmit missing segment

                self.tcp_state = TCP_State.FAST_RECOV

        print(f"==>Dup ACK: {self.tcp_state} cwnd={int(self.cwnd * MSS)} ssthresh={int(self.ssthresh * MSS)}")

    def tcp_handle_new_ack(self):
        self.dup_ack_cnt = 0

        if self.tcp_state == TCP_State.FAST_RECOV:
            self.cwnd = self.ssthresh
            self.tcp_state = TCP_State.CONG_AVOID
        # If in SLOW_START or CONG_AVOID
        else:
            self.cwnd += 1
            if self.cwnd >= self.ssthresh and self.state == TCP_State.SLOW_START:
                self.tcp_state = TCP_State.CONG_AVOID 
            # todo transmit new segments as allowed

        print(f"==>New ACK: {self.tcp_state} cwnd={int(self.cwnd * MSS)} ssthresh={int(self.ssthresh * MSS)}")

               


    def send_segment(self, data):
        """
        Sends 'data' by breaking it into MSS-sized segments, and sends them using a sliding window protocol.
        """
        total_len = len(data)
        segments = []  # List to hold all segments (Packet objects)
        offset = 0
        seq = self.window["next_seq_to_send"]

        # Initialize TCP state control variables
        self.tcp_state = TCP_State.SLOW_START
        self.cwnd = WINDOW_INITIAL_WINDOW_SIZE / MSS
        self.ssthresh = WINDOW_INITIAL_SSTHRESH / MSS
        self.dup_ack_cnt = 0
        
        # 1. Segment the data into MSS-sized packets.
        while offset < total_len:
            payload_len = min(MSS, total_len - offset)
            chunk = data[offset: offset + payload_len]
            # Create a packet; note: the ack value will be set by the sender as needed.
            packet = Packet(seq=seq, ack=self.window["last_ack"], flags=0, payload=chunk)
            segments.append(packet)
            seq += payload_len  # Advance the sequence number by the payload length
            offset += payload_len

        # Update next sequence to send (for future transmissions)
        self.window["next_seq_to_send"] = seq

        # Sliding window parameters:
        base = 0            # Index of the first unacknowledged segment (LAR + 1)
        LFS = 0             # Index of the next segment to send

        # 2. Enter the send loop.
        while base < len(segments):
            # Send segments until the window is full or we've sent all segments.
            while LFS < len(segments) and (LFS - base) < min(self.window["sws"], MAX_NETWORK_BUFFER / MSS, self.window["adv_window"]):
                seg = segments[LFS]
                ack_goal = seg.seq + len(seg.payload)
                # Record the send time for RTT calculations.
                self.packet_send_times[ack_goal] = time.time()
                print(f"Sending segment: seq={seg.seq}, len={len(seg.payload)}")
                self.sock_fd.sendto(seg.encode(), self.conn)
                LFS += 1

            # 3. Wait for the cumulative ACK for the base segment.
            # The expected ACK value is the base segment's sequence number plus its payload length.
            ack_goal = segments[base].seq + len(segments[base].payload)
            if self.wait_for_ack(ack_goal):
                print(f"Segment with seq {segments[base].seq} acknowledged.")
                base += 1  # Slide the window forward (cumulative ACK)
            else:
                # Timeout occurred; retransmit all segments in the window.

                # todo TK timeout event
                self.tcp_handle_timeout

                print("Timeout: Retransmitting segments in the current window.")
                for i in range(base, LFS):
                    seg = segments[i]
                    ack_goal = seg.seq + len(seg.payload)
                    self.packet_send_times[ack_goal] = time.time()  # Reset timer
                    print(f"Retransmitting segment: seq={seg.seq}, len={len(seg.payload)}")
                    self.sock_fd.sendto(seg.encode(), self.conn)

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
                self.wait_cond.wait(timeout=remaining)

            # ACK has been received, now calculate RTT
            send_time = self.packet_send_times.get(ack_goal, None)
            if send_time is not None:
                sample_rtt = time.time() - send_time
                # Remove it from the dict so we don't reuse it
                del self.packet_send_times[ack_goal]

                # Update est_rtt with EWMA:
                # est_rtt = alpha * est_rtt + (1 - alpha) * sample_rtt
                self.est_rtt = self.alpha * self.est_rtt + (1.0 - self.alpha) * sample_rtt

                # Optionally set timeout as some multiple of est_rtt
                self.timeout = 2 * self.est_rtt
                print(f"Updated RTT: sample={sample_rtt:.4f}, est_rtt={self.est_rtt:.4f}, timeout={self.timeout:.4f}")
            return True
        
    def send_ack(self, packet, flags, addr):
        ack_val = packet.seq + len(packet.payload)
        window = int ( (MAX_NETWORK_BUFFER / MSS) - len(self.data_buffer) ) # todo check this is correct eqn
        ack_packet = Packet(seq=packet.ack, ack=ack_val, flags=flags, window=window)
        self.sock_fd.sendto(ack_packet.encode(), addr)
        # Update last_ack
        self.window["last_ack"] = ack_val
        return ack_packet

    def deliver_buffered_packets(self):
        """
        Checks the buffered out-of-order segments and delivers any that now
        fit into the in-order sequence.
        """
        delivered = True
        while delivered:
            delivered = False
            # Look for a packet with the exact sequence number we expect next
            expected_seq = self.window["last_ack"]
            for packet in self.data_buffer:
                if packet.seq == expected_seq:
                    print(f"Delivering buffered packet: seq={packet.seq}")
                    self.window["recv_buf"] += packet.payload
                    self.window["recv_len"] += len(packet.payload)
                    self.window["last_ack"] += len(packet.payload)
                    self.data_buffer.remove(packet)
                    delivered = True
                    break


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

                    if time.time() - self.close_timer > 2 * self.est_rtt:   # todo 2*segment timeout
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
                                
                                self.last_ack_packet = self.send_ack(packet, SYN_FLAG+ACK_FLAG, addr)
                                self.ack_timer = time.time()

                                self.state = State.SYN_RCVD
                                self.wait_cond.notify_all()
                                continue
                                

                    case(State.SYN_SENT):

                        if time.time() - self.ack_timer > self.est_rtt:
                            self.sock_fd.sendto(self.last_ack_packet.encode(), addr)
                            self.ack_timer = time.time()

                        # If we get a SYN+ACK
                        if packet.flags & (SYN_FLAG + ACK_FLAG) != 0:
                            with self.recv_lock:
                                # Send back an ack
                                print("==> SYN_SENT Received SYN+ACK transitioning to ESTABLISHED")
                                self.last_ack_packet = self.send_ack(packet, ACK_FLAG, addr)
                                self.ack_timer = time.time()
                                
                                self.state = State.ESTABLISHED
                                self.wait_cond.notify_all()
                                continue

                        # If we get just a SYN
                        elif packet.flags & SYN_FLAG != 0:
                            with self.recv_lock:
                                # send syn ack
                                print("==> SYN Received SYN, sending SYN+ACK. Trans. to SYN_RCVD")
                                self.last_ack_packet = self.send_ack(packet, SYN_FLAG+ACK_FLAG, addr)
                                self.ack_timer = time.time()

                                self.state = State.SYN_RCVD
                                self.wait_cond.notify_all()
                                continue


                    case(State.SYN_RCVD):

                        if time.time() - self.ack_timer > self.est_rtt:
                            self.sock_fd.sendto(self.last_ack_packet.encode(), addr)
                            self.ack_timer = time.time()

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
                                # todo only if no data is left


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
                                    self.window["adv_window"] = packet.window # todo TK make sure this is in unit of frames
                                    # todo TK fsm handle new ACK
                                    self.tcp_handle_new_ack()
                                    print(f"New ACK window={packet.window * MSS}")
                                else:
                                    # todo TK fsm handle duplicate ACK
                                    self.tcp_handle_dup_ack
                                self.wait_cond.notify_all()
                            continue

                        # Otherwise, assume it is a data packet
                        # Check if the sequence matches our 'last_ack' (in-order data)
                        with self.recv_lock:
                            # Check if the packet is the one we expect
                            expected_seq = self.window["last_ack"]  # or a dedicated variable, e.g., NFE
                            if packet.seq == expected_seq:
                                # Deliver packet payload immediately
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)
                                print(f"Received in-order segment: seq={packet.seq}, len={len(packet.payload)}")
                                # Advance expected sequence number (cumulative ACK)
                                self.window["last_ack"] += len(packet.payload)
                                
                                # Check buffered packets for any that can now be delivered in order
                                self.deliver_buffered_packets()
                                
                                # Send a cumulative ACK for the new last_ack value
                                self.send_ack(packet, ACK_FLAG, addr)
                                
                            elif packet.seq > expected_seq:
                                # Out-of-order segment: buffer it if not already buffered
                                if not any(p.seq == packet.seq for p in self.data_buffer):
                                    print(f"Buffering out-of-order segment: seq={packet.seq}")
                                    self.add_to_buffer(packet)
                                # Send a duplicate ACK indicating expected_seq (last_ack)
                                self.send_ack(packet, ACK_FLAG, addr)
                                
                            else:
                                # Duplicate or old packet: simply resend ACK
                                print(f"Duplicate/old segment: seq={packet.seq}, expected={expected_seq}")
                                self.send_ack(packet, ACK_FLAG, addr)

                            self.wait_cond.notify_all()
                            continue

                    case(State.FIN_SENT):
                        # if packet.flags & 0 != 0:
                        #     with self.recv_lock:
                        #         print("==> FIN_SENT Received segment, transitioning to ESTABLISHED")
                        #         # Still handle the data (vv copied from established vv)
                        #         # -------------------------------------------------
                        #         # Check if the sequence matches our 'last_ack' (in-order data)
                        #         if packet.seq == self.window["last_ack"]:
                        #             with self.recv_lock:
                        #                 # Append payload to our receive buffer
                        #                 self.window["recv_buf"] += packet.payload
                        #                 self.window["recv_len"] += len(packet.payload)

                        #             with self.wait_cond:
                        #                 self.wait_cond.notify_all()

                        #             print(f"Received segment {packet.seq} with {len(packet.payload)} bytes.")

                        #             # Send back an acknowledgment & Update last ACK
                        #             self.send_ack(packet, ACK_FLAG, addr)
                        #         # -------------------------------------------------
                        #         self.state = State.ESTABLISHED
                        #         self.wait_cond.notify_all()
                        #         continue

                        # If we get an ACK packet, transition to TIME_WAIT
                        if packet.flags & ACK_FLAG != 0:
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

                        # If packet is not FIN or ACK, it must be a data packet atp

                        # run handle packet
                        # run send ack

                        if packet.flags & 0x00 != 0: # todo: Find out if this works
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
                        if packet.flags & ACK_FLAG !=0:
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

