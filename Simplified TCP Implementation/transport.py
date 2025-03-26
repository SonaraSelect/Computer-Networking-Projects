import socket
import struct
import threading
import time  
from enum import Enum, auto
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# Flags for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag (not used here)

EXIT_SUCCESS = 0
EXIT_ERROR = 1

# Basic read modes
class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

# TCP-like states
class ConnectionState(Enum):
    CLOSED      = auto()
    LISTEN      = auto()
    SYN_SENT    = auto()
    SYN_RCVD    = auto()
    ESTABLISHED = auto()
    FIN_SENT    = auto()      # Active close
    CLOSE_WAIT  = auto()      # Remote closed first
    LAST_ACK    = auto()      # We closed after peer
    TIME_WAIT   = auto()

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b"", win=0):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload
        self.win = win  # For receiver’s advertised window if you wish

    def encode(self):
        # We'll store: seq, ack, flags, win, length(payload)
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

        # Synchronization
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        # TCP-like state variables
        self.state = ConnectionState.CLOSED

        # Sequence number bookkeeping:
        #   last_ack:       receiver’s next expected seq (cumulative ACK)
        #   next_seq_expected: sender’s highest cumulative ACK
        #   next_seq_to_send:  sender’s next seq to use
        #   recv_buf:       in-order data buffer
        #   recv_len:       size of recv_buf
        self.window = {
            "last_ack": 0,
            "next_seq_expected": 0,
            "recv_buf": b"",
            "recv_len": 0,
            "next_seq_to_send": 0,
        }

        # Connection info
        self.sock_type = None
        self.conn = None
        self.my_port = None

        # RTT Estimation (EWMA)
        self.estimated_rtt = DEFAULT_TIMEOUT / 2  
        self.timeout = 2 * self.estimated_rtt       
        self.alpha = 0.5

        # Sliding window / unacked segments
        self.unacked_segments = {}
        self.advertised_window = MAX_NETWORK_BUFFER  # if you use receiver flow control

        # Timeout for TIME_WAIT (2×MSL). Here we’ll just use 2× our dynamic timeout
        self.time_wait_duration = 2 * self.timeout

    def socket(self, sock_type, port, server_ip=None):
        """
        Initialize the socket and start the backend thread.
        Depending on sock_type, we either go to LISTEN or initiate a SYN handshake.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
            self.state = ConnectionState.LISTEN
            print("Socket state: LISTEN")
        elif sock_type == "TCP_INITIATOR":
            self.sock_fd.bind(("", 0))  # ephemeral local port
            self.conn = (server_ip, port)
            # Begin active open -> send SYN
            self.state = ConnectionState.SYN_SENT
            print("Socket state: SYN_SENT")
            self.send_syn()
        else:
            print("Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can poll
        self.sock_fd.settimeout(1.0)
        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def send_syn(self):
        """
        Send a SYN packet to initiate a connection (active open).
        """
        with self.send_lock:
            # Use next_seq_to_send as the SYN sequence
            seq_no = self.window["next_seq_to_send"]
            syn_packet = Packet(seq=seq_no, ack=0, flags=SYN_FLAG, payload=b"")
            self.sock_fd.sendto(syn_packet.encode(), self.conn)
            # We consider the SYN as "one byte" of sequence space
            self.unacked_segments[seq_no] = (syn_packet, time.time(), 1)
            self.window["next_seq_to_send"] += 1

    def send_syn_ack(self):
        """
        Send a SYN+ACK from the LISTEN or SYN_RCVD state.
        """
        with self.send_lock:
            seq_no = self.window["next_seq_to_send"]
            syn_ack = Packet(seq=seq_no, ack=self.window["last_ack"], flags=(SYN_FLAG | ACK_FLAG))
            self.sock_fd.sendto(syn_ack.encode(), self.conn)
            self.unacked_segments[seq_no] = (syn_ack, time.time(), 1)
            self.window["next_seq_to_send"] += 1

    def send_ack(self, ack_val=None):
        """
        Send a simple ACK packet for in-order data or handshake completion.
        """
        with self.send_lock:
            if ack_val is None:
                ack_val = self.window["last_ack"]
            ack_pkt = Packet(seq=0, ack=ack_val, flags=ACK_FLAG)
            self.sock_fd.sendto(ack_pkt.encode(), self.conn)

    def send_fin(self):
        """
        Send a FIN packet to close the connection actively.
        """
        with self.send_lock:
            seq_no = self.window["next_seq_to_send"]
            fin_packet = Packet(seq=seq_no, ack=self.window["last_ack"], flags=FIN_FLAG)
            self.sock_fd.sendto(fin_packet.encode(), self.conn)
            # FIN consumes one sequence number
            self.unacked_segments[seq_no] = (fin_packet, time.time(), 1)
            self.window["next_seq_to_send"] += 1
        print("Sent FIN")

    def close(self):
        """
        Close the connection. If we are in ESTABLISHED, we do an active close.
        If we’re in CLOSE_WAIT, we finish the close (LAST_ACK).
        """
        with self.death_lock:
            if self.state == ConnectionState.ESTABLISHED:
                # Active close
                self.state = ConnectionState.FIN_SENT
                self.send_fin()
            elif self.state == ConnectionState.CLOSE_WAIT:
                # We received a FIN already; we now respond with FIN
                self.state = ConnectionState.LAST_ACK
                self.send_fin()
            else:
                # If we’re not in a state that expects a FIN exchange, just mark dying
                print(f"close() called in state={self.state.name}, shutting down.")
                self.dying = True
                if self.thread:
                    self.thread.join()
                if self.sock_fd:
                    self.sock_fd.close()
                return EXIT_SUCCESS

        # Let the background thread handle the transitions to TIME_WAIT or CLOSED.
        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data in the ESTABLISHED state using your sliding window mechanism.
        """
        if self.state != ConnectionState.ESTABLISHED:
            print(f"Cannot send data while in state {self.state.name}.")
            return
        if not self.conn:
            raise ValueError("Connection not established.")
        # Reuse your existing sliding-window logic or stop-and-wait logic
        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf, length, flags):
        """
        Receive data from the in-order buffer.
        """
        read_len = 0
        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0 and self.state == ConnectionState.ESTABLISHED:
                    self.wait_cond.wait()

        with self.recv_lock:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]
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

    def send_segment(self, data):
        """
        Example of sending data with a simple or sliding window approach.
        (You can reuse your existing logic here.)
        """
        offset = 0
        total_len = len(data)

        while offset < total_len or self.unacked_segments:
            # For brevity, we show a simple approach that sends one segment at a time
            # then waits for an ACK. You can replace with your sliding window approach.
            if offset < total_len:
                payload_len = min(MSS, total_len - offset)
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset: offset + payload_len]
                segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, payload=chunk)
                self.sock_fd.sendto(segment.encode(), self.conn)
                self.unacked_segments[seq_no] = (segment, time.time(), payload_len)
                self.window["next_seq_to_send"] += payload_len
                offset += payload_len
                print(f"Sent data segment seq={seq_no}, len={payload_len}")

            # Wait briefly to allow ACK processing or re‑send on timeout
            with self.wait_cond:
                self.wait_cond.wait(timeout=0.1)

            # Check for timed-out segments
            now = time.time()
            for s, (pkt, sent_time, seg_len) in list(self.unacked_segments.items()):
                if now - sent_time > self.timeout:
                    print(f"Timeout: Retransmitting seq={s}")
                    self.sock_fd.sendto(pkt.encode(), self.conn)
                    self.unacked_segments[s] = (pkt, time.time(), seg_len)

    def backend(self):
        """
        Main loop that handles incoming packets and transitions between states.
        """
        while not self.dying:
            # If we are in TIME_WAIT, wait 2×MSL, then close
            if self.state == ConnectionState.TIME_WAIT:
                print("In TIME_WAIT; waiting to close.")
                time.sleep(self.time_wait_duration)
                self.state = ConnectionState.CLOSED
                self.dying = True
                break

            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer, set it
                if self.conn is None:
                    self.conn = addr

                # Check flags
                syn = bool(packet.flags & SYN_FLAG)
                ack = bool(packet.flags & ACK_FLAG)
                fin = bool(packet.flags & FIN_FLAG)

                # --------------------------------------
                # HANDSHAKE & STATE TRANSITIONS
                # --------------------------------------
                if self.state == ConnectionState.LISTEN:
                    # Expecting a SYN from a client
                    if syn and not ack:
                        # We got a SYN, go to SYN_RCVD, send SYN+ACK
                        self.state = ConnectionState
