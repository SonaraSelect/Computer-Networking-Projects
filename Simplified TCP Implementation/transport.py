import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER
from enum import Enum, auto

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
    def __init__(self, seq=0, ack=0, flags=0, payload=b"", win=0):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload
        self.win = win  # Receiver's advertised window (in ACK packets)

    def encode(self):
        # New header: seq, ack, flags, win, and payload length
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
        self.recv_lock = threading.Lock()                    # For synchronizing receiver state
        self.send_lock = threading.Lock()                    # For synchronizing sender state
        self.wait_cond = threading.Condition(self.recv_lock) # To signal state changes

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        # Combined state for sender and receiver.
        # For receiver:
        #    "last_ack" is the next sequence number expected (i.e. cumulative ACK to send)
        #    "recv_buf" and "recv_len" hold the in-order received data.
        # For sender:
        #    "next_seq_expected" is the highest cumulative ACK received (i.e. sender's base)
        #    "next_seq_to_send" is the sequence number to be assigned to the next outgoing segment.
        self.window = {
            "last_ack": 0,            # Receiver: next expected seq (i.e. cumulative ACK value)
            "next_seq_expected": 0,   # Sender: highest cumulative ACK received so far
            "recv_buf": b"",          # Receiver: buffer for in-order data
            "recv_len": 0,            # Receiver: current size of recv_buf
            "next_seq_to_send": 0,    # Sender: next sequence number to use
        }

        self.sock_type = None
        self.conn = None
        self.my_port = None

        # RTT estimation variables (using EWMA)
        self.estimated_rtt = DEFAULT_TIMEOUT / 2  
        self.timeout = 2 * self.estimated_rtt       
        self.alpha = 0.5                            

        # Sender sliding window state:
        # unacked_segments: dictionary mapping starting seq -> (Packet, send_time, payload_len)
        # Outstanding bytes = next_seq_to_send - next_seq_expected.
        self.unacked_segments = {}

        # Receiver's advertised window (in bytes). Initially, the receiver can buffer up to MAX_NETWORK_BUFFER.
        self.advertised_window = MAX_NETWORK_BUFFER

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

        # Use a 1-second timeout so we can periodically check `self.dying`
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
        with self.death_lock:
            self.dying = True

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            print("Error: Null socket")
            return EXIT_ERROR

        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data reliably to the peer using a sliding window mechanism.
        """
        if not self.conn:
            raise ValueError("Connection not established.")
        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf, length, flags):
        """
        Retrieve received data from the buffer, with optional blocking behavior.
        """
        read_len = 0

        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        # Blocking read: wait until data is available.
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    self.wait_cond.wait()

        with self.recv_lock:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]
                    # Remove data from the buffer after reading.
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
        Send 'data' by breaking it into MSS-sized segments while enforcing a sliding window:
          - The sender will not have more outstanding data than the receiver's advertised window.
          - Each segment is retransmitted if an ACK is not received within the current timeout.
        """
        offset = 0
        total_len = len(data)

        # Continue until all data is sent and all outstanding segments are acknowledged.
        while offset < total_len or self.unacked_segments:
            with self.send_lock:
                # Calculate outstanding bytes (bytes sent but not yet acknowledged).
                outstanding = self.window["next_seq_to_send"] - self.window["next_seq_expected"]
                available_window = self.advertised_window - outstanding

                # Send new segments if data remains and window space is available.
                while offset < total_len and available_window > 0:
                    payload_len = min(MSS, total_len - offset, available_window)
                    seq_no = self.window["next_seq_to_send"]
                    chunk = data[offset: offset + payload_len]
                    # Create a data packet (flags=0) – 'win' is not used in data packets.
                    segment = Packet(seq=seq_no, ack=0, flags=0, payload=chunk, win=0)
                    self.sock_fd.sendto(segment.encode(), self.conn)
                    # Record the segment for possible retransmission.
                    self.unacked_segments[seq_no] = (segment, time.time(), payload_len)
                    self.window["next_seq_to_send"] += payload_len
                    offset += payload_len
                    outstanding = self.window["next_seq_to_send"] - self.window["next_seq_expected"]
                    available_window = self.advertised_window - outstanding
                    print(f"Sent segment: seq={seq_no}, len={payload_len}, outstanding={outstanding}")

            # Wait a short time or until notified by an ACK.
            with self.wait_cond:
                self.wait_cond.wait(timeout=0.1)

            # Check for timeout and retransmit any segments that have timed out.
            now = time.time()
            for seq, (segment, sent_time, seg_len) in list(self.unacked_segments.items()):
                if now - sent_time >= self.timeout:
                    print(f"Timeout: Retransmitting segment with seq={seq}")
                    self.sock_fd.sendto(segment.encode(), self.conn)
                    self.unacked_segments[seq] = (segment, now, seg_len)

    def wait_for_ack(self, ack_goal, timeout=None):
        """
        (Not used in sliding window mode; kept for compatibility.)
        """
        with self.recv_lock:
            start = time.time()
            effective_timeout = timeout if timeout is not None else self.timeout
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = effective_timeout - elapsed
                if remaining <= 0:
                    return False
                self.wait_cond.wait(timeout=remaining)
            return True

    def backend(self):
        """
        Backend loop to handle incoming packets and send acknowledgments.
        This thread is the sole reader of incoming packets.
        """
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr

                # Process ACK packets (sender side)
                if (packet.flags & ACK_FLAG) != 0:
                    with self.wait_cond:
                        # Update sender's cumulative ACK (next_seq_expected) if this ACK is higher.
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                        # Update the receiver's advertised window from the ACK.
                        self.advertised_window = packet.win
                        # Remove acknowledged segments from our retransmission buffer.
                        for seq in list(self.unacked_segments.keys()):
                            if seq < packet.ack:
                                del self.unacked_segments[seq]
                        self.wait_cond.notify_all()
                    print(f"Received ACK: ack={packet.ack}, advertised_window={packet.win}")
                    continue

                # Otherwise, assume this is a data packet (receiver side).
                # Accept data only if it is the expected packet.
                if packet.seq == self.window["last_ack"]:
                    with self.recv_lock:
                        # Enforce the maximum buffer size.
                        if self.window["recv_len"] + len(packet.payload) > MAX_NETWORK_BUFFER:
                            print("Receive buffer full. Dropping packet.")
                            available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG, payload=b"", win=available)
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                        else:
                            self.window["recv_buf"] += packet.payload
                            self.window["recv_len"] += len(packet.payload)
                            with self.wait_cond:
                                self.wait_cond.notify_all()
                            print(f"Received segment: seq={packet.seq}, len={len(packet.payload)}")
                            # Compute cumulative ACK for in-order data.
                            ack_val = packet.seq + len(packet.payload)
                            available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(seq=0, ack=ack_val, flags=ACK_FLAG, payload=b"", win=available)
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            self.window["last_ack"] = ack_val
                else:
                    # Out-of-order packet (in this basic implementation we discard it)
                    print(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")

            except socket.timeout:
                continue
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")
