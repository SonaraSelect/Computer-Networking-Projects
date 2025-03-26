import socket
import struct
import threading
import time
from enum import Enum, auto
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# -------------------------
# Constants and Flags
# -------------------------
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

# For TIME_WAIT, we need a 2×MSL timeout.
# In a real TCP, MSL might be 30 seconds or more.
# Here, we’ll use a small value for demonstration.
MSL = 2   # seconds

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class TCPState(Enum):
    CLOSED      = auto()
    LISTEN      = auto()
    SYN_SENT    = auto()
    SYN_RCVD    = auto()
    ESTABLISHED = auto()
    FIN_SENT    = auto()     # We combine FIN_WAIT1/2 into a single state for simplicity
    CLOSE_WAIT  = auto()
    LAST_ACK    = auto()
    TIME_WAIT   = auto()

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b"", win=0):
        """
        :param seq:  Sender's sequence number
        :param ack:  Acknowledgment number
        :param flags: Combination of SYN_FLAG, ACK_FLAG, FIN_FLAG, etc.
        :param payload: Actual data
        :param win: Advertised window (used for flow control)
        """
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload
        self.win = win

    def encode(self):
        """
        Encode the packet header and payload into bytes.
        Header format: seq (4 bytes), ack (4 bytes), flags (4 bytes),
                       win (4 bytes), payload_len (2 bytes).
        """
        header = struct.pack("!IIIIH", self.seq, self.ack, self.flags, self.win, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        header_size = struct.calcsize("!IIIIH")
        seq, ack, flags, win, payload_len = struct.unpack("!IIIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, payload, win)

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

        # -------------------------
        # Internal sliding window state
        # -------------------------
        self.window = {
            "last_ack": 0,            # Receiver: next expected seq (cumulative ACK)
            "next_seq_expected": 0,   # Sender: highest cumulative ACK received
            "recv_buf": b"",          # Receiver: buffer for in-order data
            "recv_len": 0,            # Size of recv_buf
            "next_seq_to_send": 0,    # Sender: next seq no. to assign
        }

        self.sock_type = None
        self.conn = None
        self.my_port = None

        # RTT estimation
        self.estimated_rtt = DEFAULT_TIMEOUT / 2  
        self.timeout = 2 * self.estimated_rtt       
        self.alpha = 0.5                            

        # Sliding window placeholders
        self.unacked_segments = {}
        self.advertised_window = MAX_NETWORK_BUFFER  # We'll track the receiver's advertised window

        # -------------------------
        # TCP FSM State
        # -------------------------
        self.state = TCPState.CLOSED
        self.time_wait_start = None  # to track TIME_WAIT start time

    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        For a real TCP-like socket, we might also want to automatically:
          - If sock_type == "TCP_LISTENER", call listen().
          - If sock_type == "TCP_INITIATOR", we might connect() automatically.
        But here we keep them separate for clarity.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            # We'll actually connect using self.connect(...) below.
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # ephemeral port
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
        else:
            print("Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can check self.dying, TIME_WAIT, etc.
        self.sock_fd.settimeout(1.0)
        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    # -------------------------
    # Active Open
    # -------------------------
    def connect(self):
        """
        Actively open a connection to the remote host.
        Implements the three-way handshake for the client side:
          1) Send SYN, move to SYN_SENT.
          2) Wait for SYN+ACK, send ACK, move to ESTABLISHED.
        """
        with self.send_lock:
            if self.state != TCPState.CLOSED:
                print(f"connect() called but state is {self.state}")
                return

            # Send SYN
            print("Sending SYN...")
            syn_packet = Packet(seq=self.window["next_seq_to_send"], flags=SYN_FLAG)
            self.sock_fd.sendto(syn_packet.encode(), self.conn)
            self.state = TCPState.SYN_SENT

    # -------------------------
    # Passive Open
    # -------------------------
    def listen(self):
        """
        Passively open a connection: move to LISTEN state.
        Wait for an incoming SYN in the backend to move to SYN_RCVD, etc.
        """
        with self.send_lock:
            if self.state != TCPState.CLOSED:
                print(f"listen() called but state is {self.state}")
                return
            self.state = TCPState.LISTEN
            print("Socket is now LISTENING...")

    # -------------------------
    # Close
    # -------------------------
    def close(self):
        """
        Initiates (or continues) closing the connection:
          - If in ESTABLISHED, send FIN, go to FIN_SENT.
          - If in CLOSE_WAIT, send FIN, go to LAST_ACK.
          - If in SYN_SENT or SYN_RCVD, we can abort/close directly (simplified).
        """
        with self.send_lock:
            if self.state == TCPState.ESTABLISHED:
                print("Sending FIN (active close from ESTABLISHED)...")
                fin_pkt = Packet(seq=self.window["next_seq_to_send"], flags=FIN_FLAG)
                self.sock_fd.sendto(fin_pkt.encode(), self.conn)
                self.state = TCPState.FIN_SENT
            elif self.state == TCPState.CLOSE_WAIT:
                print("Sending FIN (close while in CLOSE_WAIT)...")
                fin_pkt = Packet(seq=self.window["next_seq_to_send"], flags=FIN_FLAG)
                self.sock_fd.sendto(fin_pkt.encode(), self.conn)
                self.state = TCPState.LAST_ACK
            else:
                # If in other states, we do a simplified "abort"
                print(f"close() called in state {self.state}. Forcing CLOSED.")
                self.state = TCPState.CLOSED

    def close_socket(self):
        """
        Force-close the underlying socket. Called after we exit the TCP FSM, or for error.
        """
        with self.death_lock:
            self.dying = True

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()

    # -------------------------
    # High-level I/O
    # -------------------------
    def send(self, data):
        """
        Send data reliably to the peer using a sliding window mechanism,
        but only if state is ESTABLISHED (or possibly FIN_SENT but not fully closed).
        """
        with self.send_lock:
            if self.state not in (TCPState.ESTABLISHED, TCPState.FIN_SENT):
                print(f"send() called but state is {self.state}; ignoring data send.")
                return
            self.send_segment(data)

    def recv(self, buf, length, flags):
        """
        Retrieve data from the receiver buffer, optionally blocking if none is available.
        """
        read_len = 0
        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        # If blocking read, wait for data
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0 and self.state == TCPState.ESTABLISHED:
                    self.wait_cond.wait()

        with self.recv_lock:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]
                    # Remove from buffer
                    if read_len < self.window["recv_len"]:
                        self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                        self.window["recv_len"] -= read_len
                    else:
                        self.window["recv_buf"] = b""
                        self.window["recv_len"] = 0
            else:
                print("ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR

        return read_len

    # -------------------------
    # Sliding Window Send
    # -------------------------
    def send_segment(self, data):
        """
        Basic sliding window send (like before). 
        Here we assume we are in or beyond ESTABLISHED. 
        """
        offset = 0
        total_len = len(data)
        while offset < total_len or self.unacked_segments:
            with self.send_lock:
                # Check outstanding vs. advertised window
                outstanding = self.window["next_seq_to_send"] - self.window["next_seq_expected"]
                available_window = self.advertised_window - outstanding

                # Send new segments if there's room
                while offset < total_len and available_window > 0:
                    payload_len = min(MSS, total_len - offset, available_window)
                    seq_no = self.window["next_seq_to_send"]
                    chunk = data[offset : offset + payload_len]
                    segment = Packet(seq=seq_no, ack=0, flags=0, payload=chunk)
                    self.sock_fd.sendto(segment.encode(), self.conn)
                    self.unacked_segments[seq_no] = (segment, time.time(), payload_len)
                    self.window["next_seq_to_send"] += payload_len
                    offset += payload_len
                    outstanding = self.window["next_seq_to_send"] - self.window["next_seq_expected"]
                    available_window = self.advertised_window - outstanding
                    print(f"Sent data segment seq={seq_no}, len={payload_len}, outstanding={outstanding}")

            # Wait or handle retransmissions
            with self.wait_cond:
                self.wait_cond.wait(timeout=0.1)

            # Check timeouts
            now = time.time()
            for seq, (seg, t_sent, seg_len) in list(self.unacked_segments.items()):
                if now - t_sent >= self.timeout:
                    print(f"Timeout: Retransmitting seq={seq}")
                    self.sock_fd.sendto(seg.encode(), self.conn)
                    self.unacked_segments[seq] = (seg, time.time(), seg_len)

    # -------------------------
    # Backend Thread
    # -------------------------
    def backend(self):
        while not self.dying:
            # 1) Check if we’re in TIME_WAIT and if so, whether we’ve timed out
            if self.state == TCPState.TIME_WAIT and self.time_wait_start is not None:
                if time.time() - self.time_wait_start >= 2 * MSL:
                    print("TIME_WAIT expired; moving to CLOSED.")
                    self.state = TCPState.CLOSED

            # 2) If we’re CLOSED, we can eventually kill the socket
            if self.state == TCPState.CLOSED:
                self.close_socket()
                return

            # 3) Attempt to receive incoming packets
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # Passive open: if we are LISTEN and receive a SYN
                if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG) != 0:
                    print("Received SYN in LISTEN; sending SYN+ACK, moving to SYN_RCVD.")
                    # Send SYN+ACK
                    syn_ack_pkt = Packet(seq=0, ack=0, flags=SYN_FLAG | ACK_FLAG)
                    self.sock_fd.sendto(syn_ack_pkt.encode(), addr)
                    self.state = TCPState.SYN_RCVD
                    self.conn = addr
                    continue

                # If we are SYN_SENT and receive a SYN+ACK
                if self.state == TCPState.SYN_SENT and (packet.flags & SYN_FLAG) and (packet.flags & ACK_FLAG):
                    print("Received SYN+ACK in SYN_SENT; sending ACK, moving to ESTABLISHED.")
                    ack_pkt = Packet(seq=0, ack=0, flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_pkt.encode(), addr)
                    self.state = TCPState.ESTABLISHED
                    continue

                # If we are SYN_RCVD and receive an ACK
                if self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG):
                    print("Received ACK in SYN_RCVD; moving to ESTABLISHED.")
                    self.state = TCPState.ESTABLISHED
                    continue

                # If we receive FIN while in ESTABLISHED => passive close
                if self.state == TCPState.ESTABLISHED and (packet.flags & FIN_FLAG):
                    print("Received FIN in ESTABLISHED; sending ACK, moving to CLOSE_WAIT.")
                    ack_pkt = Packet(flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_pkt.encode(), addr)
                    self.state = TCPState.CLOSE_WAIT
                    continue

                # If we are FIN_SENT and receive FIN+ACK => we go to TIME_WAIT
                if self.state == TCPState.FIN_SENT and (packet.flags & FIN_FLAG) and (packet.flags & ACK_FLAG):
                    print("Received FIN+ACK in FIN_SENT; sending ACK, moving to TIME_WAIT.")
                    ack_pkt = Packet(flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_pkt.encode(), addr)
                    self.state = TCPState.TIME_WAIT
                    self.time_wait_start = time.time()
                    continue

                # If we are FIN_SENT and receive just ACK => might be half-close
                if self.state == TCPState.FIN_SENT and (packet.flags & ACK_FLAG) and not (packet.flags & FIN_FLAG):
                    # The peer has ACKed our FIN, but not sent its own FIN yet
                    print("Received ACK in FIN_SENT (no FIN). Connection half-closed from our side.")
                    # We remain in FIN_SENT until the other side’s FIN arrives or a timer runs out.
                    continue

                # If we are CLOSE_WAIT and we get close() => code in close() sets LAST_ACK
                # If we get a FIN from the other side in CLOSE_WAIT, it’s unusual in standard TCP, but we can handle it.
                if self.state == TCPState.CLOSE_WAIT and (packet.flags & FIN_FLAG):
                    # We’re both trying to close. We might send an ACK and remain in CLOSE_WAIT or go to LAST_ACK.
                    print("Received FIN in CLOSE_WAIT (simultaneous close?). Sending ACK.")
                    ack_pkt = Packet(flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_pkt.encode(), addr)
                    # Typically we’d move to LAST_ACK, or wait for user’s close.
                    continue

                # If we are LAST_ACK and receive an ACK => we go to CLOSED
                if self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG):
                    print("Received final ACK in LAST_ACK; moving to CLOSED.")
                    self.state = TCPState.CLOSED
                    continue

                # Handle normal data/ACK for established or fin-sent states
                self.handle_incoming_packet(packet, addr)

            except socket.timeout:
                # Check again for TIME_WAIT or dying
                continue
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")

    # -------------------------
    # handle_incoming_packet
    # -------------------------
    def handle_incoming_packet(self, packet, addr):
        """
        Handle data or ACK packets if we are in an appropriate state 
        (e.g., ESTABLISHED, FIN_SENT).
        """
        # If it's an ACK, update sender side
        if (packet.flags & ACK_FLAG) != 0 and not (packet.flags & SYN_FLAG or packet.flags & FIN_FLAG):
            with self.wait_cond:
                if packet.ack > self.window["next_seq_expected"]:
                    self.window["next_seq_expected"] = packet.ack
                # Possibly update advertised window
                self.advertised_window = packet.win
                # Remove acked segments
                for seq in list(self.unacked_segments.keys()):
                    if seq < packet.ack:
                        del self.unacked_segments[seq]
                self.wait_cond.notify_all()
            print(f"Received pure ACK: ack={packet.ack}, advertised_window={packet.win}")
            return

        # If it's a FIN (but we didn’t catch it in the main loop), handle quickly
        if (packet.flags & FIN_FLAG) != 0:
            print("Received FIN (unhandled in main loop). Sending ACK.")
            fin_ack = Packet(flags=ACK_FLAG)
            self.sock_fd.sendto(fin_ack.encode(), addr)
            # Depending on state, might need to set something. For simplicity, do nothing here.
            return

        # Otherwise, treat it as data for the receiver side
        if packet.seq == self.window["last_ack"]:
            with self.recv_lock:
                if self.window["recv_len"] + len(packet.payload) > MAX_NETWORK_BUFFER:
                    print("Receive buffer full. Dropping data.")
                    available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    ack_pkt = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG, win=available)
                    self.sock_fd.sendto(ack_pkt.encode(), addr)
                else:
                    self.window["recv_buf"] += packet.payload
                    self.window["recv_len"] += len(packet.payload)
                    with self.wait_cond:
                        self.wait_cond.notify_all()
                    ack_val = packet.seq + len(packet.payload)
                    available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    ack_pkt = Packet(seq=0, ack=ack_val, flags=ACK_FLAG, win=available)
                    self.sock_fd.sendto(ack_pkt.encode(), addr)
                    self.window["last_ack"] = ack_val
                    print(f"Received data seq={packet.seq}, len={len(packet.payload)}")
        else:
            print(f"Out-of-order data: seq={packet.seq}, expected={self.window['last_ack']}")
