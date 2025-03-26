import socket
import struct
import threading
import time
from enum import Enum, auto
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# Flags for simplified TCP
SYN_FLAG = 0x8
ACK_FLAG = 0x4
FIN_FLAG = 0x2
# (SACK_FLAG = 0x1 not used in this example, but could be extended.)

EXIT_SUCCESS = 0
EXIT_ERROR = 1

MSL = 2  # Maximum Segment Lifetime in seconds (example); TIME_WAIT = 2 * MSL = 4s

class TCPState(Enum):
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RCVD = auto()
    ESTABLISHED = auto()
    FIN_SENT = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class Packet:
    """
    We'll keep the 'win' field from the sliding-window version to
    carry the receiver's advertised window in ACK packets.
    """
    def __init__(self, seq=0, ack=0, flags=0, payload=b"", win=0):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload
        self.win = win  # For flow control

    def encode(self):
        # Header: seq, ack, flags, win, and payload length
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

        # State machine
        self.state = TCPState.CLOSED

        # Locks and condition
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        # Combined state for sending/receiving
        self.window = {
            "last_ack": 0,            # Receiver's next expected seq (for in-order data)
            "next_seq_expected": 0,   # Sender's highest cumulative ACK
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # Current size of recv_buf
            "next_seq_to_send": 0,    # Next seq number to use for new data
        }

        self.sock_type = None
        self.conn = None
        self.my_port = None

        # RTT estimation
        self.estimated_rtt = DEFAULT_TIMEOUT / 2
        self.timeout = 2 * self.estimated_rtt
        self.alpha = 0.5

        # Sliding window data
        self.unacked_segments = {}
        self.advertised_window = MAX_NETWORK_BUFFER

    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and
        starting the backend thread. Also initiates the TCP-like
        connection if needed (SYN).
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_fd.settimeout(1.0)  # 1s timeout for checking self.dying

        self.sock_type = sock_type
        if sock_type == "TCP_LISTENER":
            self.state = TCPState.LISTEN
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))

        elif sock_type == "TCP_INITIATOR":
            self.state = TCPState.CLOSED  # We'll do active open below
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # ephemeral local port
            self._active_open()         # send SYN

        else:
            print("Unknown socket type")
            return EXIT_ERROR

        self.my_port = self.sock_fd.getsockname()[1]
        # Start backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def _active_open(self):
        """
        For the initiator: move from CLOSED to SYN_SENT,
        send SYN to the server, wait for SYN+ACK in backend.
        """
        with self.send_lock:
            print("Active open: sending SYN...")
            self.state = TCPState.SYN_SENT
            syn_segment = Packet(seq=self.window["next_seq_to_send"], flags=SYN_FLAG)
            self.sock_fd.sendto(syn_segment.encode(), self.conn)

    def _passive_open_syn_rcvd(self, addr, incoming_seq):
        """
        For the listener: move from LISTEN to SYN_RCVD, send SYN+ACK.
        """
        with self.send_lock:
            print("Passive open: received SYN, replying with SYN+ACK...")
            self.conn = addr  # record peer
            self.state = TCPState.SYN_RCVD
            # We'll use our "next_seq_to_send" as the SYN+ACK seq
            self.window["next_seq_to_send"] = 1000  # arbitrary initial seq
            syn_ack_segment = Packet(
                seq=self.window["next_seq_to_send"],
                ack=incoming_seq + 1,
                flags=SYN_FLAG | ACK_FLAG
            )
            self.sock_fd.sendto(syn_ack_segment.encode(), addr)

    def close(self):
        """
        Initiates a close. Depending on the current state:
          - If ESTABLISHED, send FIN, go to FIN_SENT (active close).
          - If CLOSE_WAIT, send FIN, go to LAST_ACK (passive close).
          - Otherwise, mark self.dying or handle final states.
        """
        with self.death_lock:
            if self.state == TCPState.ESTABLISHED:
                print("close() called in ESTABLISHED => sending FIN, going to FIN_SENT")
                self._send_fin()
                self.state = TCPState.FIN_SENT
            elif self.state == TCPState.CLOSE_WAIT:
                print("close() called in CLOSE_WAIT => sending FIN, going to LAST_ACK")
                self._send_fin()
                self.state = TCPState.LAST_ACK
            else:
                print(f"close() called in state={self.state.name}. Moving to CLOSED.")
                self.state = TCPState.CLOSED
                self.dying = True

        if self.thread and self.state == TCPState.CLOSED:
            self.thread.join()
            if self.sock_fd:
                self.sock_fd.close()
            return EXIT_SUCCESS
        return EXIT_SUCCESS

    def _send_fin(self):
        with self.send_lock:
            fin_segment = Packet(
                seq=self.window["next_seq_to_send"],
                ack=self.window["next_seq_expected"],
                flags=FIN_FLAG
            )
            self.sock_fd.sendto(fin_segment.encode(), self.conn)
            # FIN consumes one sequence number
            self.window["next_seq_to_send"] += 1

    def send(self, data):
        """
        Send data in the ESTABLISHED state using sliding window.
        """
        if not self.conn:
            raise ValueError("Connection not established.")
        if self.state != TCPState.ESTABLISHED:
            print(f"Warning: Attempt to send in state={self.state.name}; ignoring.")
            return
        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf, length, flags):
        """
        Retrieve received data from the buffer, with optional blocking.
        """
        read_len = 0
        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0 and not self.dying:
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

    def send_segment(self, data):
        """
        Sliding-window send of 'data'.  
        We assume the connection is ESTABLISHED when this is called.
        """
        offset = 0
        total_len = len(data)

        while offset < total_len or self.unacked_segments:
            with self.send_lock:
                outstanding = self.window["next_seq_to_send"] - self.window["next_seq_expected"]
                available_window = self.advertised_window - outstanding

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
                    print(f"Sent segment: seq={seq_no}, len={payload_len}, outstanding={outstanding}")

            # Wait or check for timeouts
            with self.wait_cond:
                self.wait_cond.wait(timeout=0.1)

            # Check for retransmissions
            now = time.time()
            for seq, (seg, t_sent, seg_len) in list(self.unacked_segments.items()):
                if now - t_sent >= self.timeout:
                    print(f"Timeout: Retransmitting segment with seq={seq}")
                    self.sock_fd.sendto(seg.encode(), self.conn)
                    self.unacked_segments[seq] = (seg, now, seg_len)

    def backend(self):
        """
        Main loop to handle incoming packets, manage handshake, teardown, etc.
        """
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)
                self._handle_packet(packet, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")

        # If we exit the loop, ensure socket is closed
        self.sock_fd.close()

    def _handle_packet(self, packet, addr):
        """
        Dispatch incoming packets based on current state and packet flags.
        """
        # 1. Handle a passive open if we are in LISTEN and get a SYN
        if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG):
            self._passive_open_syn_rcvd(addr, packet.seq)
            return

        # 2. If we are in SYN_SENT and we receive a SYN+ACK
        if self.state == TCPState.SYN_SENT and (packet.flags & SYN_FLAG) and (packet.flags & ACK_FLAG):
            # Acknowledge the SYN+ACK
            print("Received SYN+ACK => sending final ACK, connection ESTABLISHED")
            self.state = TCPState.ESTABLISHED
            self.conn = addr
            ack_seg = Packet(
                seq=self.window["next_seq_to_send"],
                ack=packet.seq + 1,
                flags=ACK_FLAG
            )
            self.sock_fd.sendto(ack_seg.encode(), addr)
            # Bump our next_seq_to_send to reflect we used one seq for the SYN
            self.window["next_seq_to_send"] += 1
            return

        # 3. If we are in SYN_RCVD and we get an ACK
        if self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG):
            print("Received ACK after SYN+ACK => connection ESTABLISHED")
            self.state = TCPState.ESTABLISHED
            return

        # 4. If in ESTABLISHED, handle data or FIN
        if self.state == TCPState.ESTABLISHED:
            if (packet.flags & FIN_FLAG):
                # Peer wants to close
                print("Received FIN in ESTABLISHED => sending ACK, entering CLOSE_WAIT")
                self._send_ack_for_fin(packet)
                self.state = TCPState.CLOSE_WAIT
                return

            # Possibly an ACK for our data
            if (packet.flags & ACK_FLAG):
                self._handle_ack(packet)
                return

            # Possibly normal data from peer
            if packet.flags == 0:
                self._handle_data(packet, addr)
                return

        # 5. If we are in FIN_SENT (active close) and receive FIN
        if self.state == TCPState.FIN_SENT:
            if (packet.flags & ACK_FLAG):
                # This might be the ACK for our FIN
                self._handle_ack(packet)
                # We still expect FIN from the peer if we closed first
            if (packet.flags & FIN_FLAG):
                print("FIN_SENT: received FIN => sending ACK, entering TIME_WAIT")
                self._send_ack_for_fin(packet)
                self.state = TCPState.TIME_WAIT
                # TIME_WAIT: wait 2 * MSL, then close
                threading.Thread(target=self._time_wait_handler).start()
            return

        # 6. If we are in CLOSE_WAIT and get more FINs (unlikely in this simplified model) 
        # or normal data, just ignore. We will close once user calls close().
        if self.state == TCPState.CLOSE_WAIT:
            if (packet.flags & FIN_FLAG):
                print("CLOSE_WAIT: received extra FIN, ignoring in this simplified model.")
            if (packet.flags & ACK_FLAG):
                self._handle_ack(packet)
            return

        # 7. If we are in LAST_ACK waiting for final ACK from peer
        if self.state == TCPState.LAST_ACK:
            if (packet.flags & ACK_FLAG):
                # Peer acked our FIN => we are done
                print("LAST_ACK: final ACK received => CLOSED")
                self.state = TCPState.CLOSED
                with self.death_lock:
                    self.dying = True
            return

        # 8. If we are in TIME_WAIT, ignore everything except maybe repeated FIN
        if self.state == TCPState.TIME_WAIT:
            if (packet.flags & FIN_FLAG):
                print("TIME_WAIT: re-ACKing FIN from peer")
                self._send_ack_for_fin(packet)
            return

    def _time_wait_handler(self):
        """
        Sleep for 2 * MSL, then transition to CLOSED.
        """
        time.sleep(2 * MSL)
        print("TIME_WAIT expired => CLOSED")
        with self.death_lock:
            self.state = TCPState.CLOSED
            self.dying = True

    def _send_ack_for_fin(self, packet):
        """
        Send an ACK in response to a FIN.
        """
        ack_val = packet.seq + 1  # FIN consumes 1 sequence number
        ack_seg = Packet(
            seq=self.window["next_seq_to_send"],
            ack=ack_val,
            flags=ACK_FLAG
        )
        self.sock_fd.sendto(ack_seg.encode(), self.conn)
        self.window["next_seq_to_send"] += 1

    def _handle_ack(self, packet):
        """
        Process an incoming ACK for the sender side.
        """
        with self.wait_cond:
            if packet.ack > self.window["next_seq_expected"]:
                self.window["next_seq_expected"] = packet.ack
            self.advertised_window = packet.win
            # Remove fully acknowledged segments
            for seq in list(self.unacked_segments.keys()):
                if seq < packet.ack:
                    del self.unacked_segments[seq]
            self.wait_cond.notify_all()

    def _handle_data(self, packet, addr):
        """
        Process normal data (flags=0) for the receiver side, if in ESTABLISHED.
        """
        if packet.seq == self.window["last_ack"]:
            with self.recv_lock:
                # Check buffer limit
                if self.window["recv_len"] + len(packet.payload) <= MAX_NETWORK_BUFFER:
                    self.window["recv_buf"] += packet.payload
                    self.window["recv_len"] += len(packet.payload)
                    print(f"Received data segment seq={packet.seq}, len={len(packet.payload)}")
                    # Advance last_ack by the size of this payload
                    new_ack = packet.seq + len(packet.payload)
                    self.window["last_ack"] = new_ack
                    with self.wait_cond:
                        self.wait_cond.notify_all()
                    # Send an ACK
                    avail = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    ack_seg = Packet(seq=0, ack=new_ack, flags=ACK_FLAG, win=avail)
                    self.sock_fd.sendto(ack_seg.encode(), addr)
                else:
                    print("Receive buffer full. Dropping data.")
                    # Still send ACK advertising minimal window
                    avail = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    ack_seg = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG, win=avail)
                    self.sock_fd.sendto(ack_seg.encode(), addr)
        else:
            # Out-of-order or duplicate data
            print(f"Out-of-order data: seq={packet.seq}, expected={self.window['last_ack']}")
            # Could send a duplicate ACK for the last_ack
            dup_ack = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG, win=MAX_NETWORK_BUFFER - self.window["recv_len"])
            self.sock_fd.sendto(dup_ack.encode(), addr)
