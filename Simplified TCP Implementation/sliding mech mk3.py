import socket
import struct
import threading
import time
from enum import Enum, auto
from grading import MSS, DEFAULT_TIMEOUT, WINDOW_SIZE, MAX_NETWORK_BUFFER

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
        self.win = win  # New field for receiver's advertised window

    def encode(self):
        # Header now contains: seq, ack, flags, win, and payload length
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

        # Locks and condition variables
        self.recv_lock = threading.Lock()                    # For synchronizing shared state
        self.send_lock = threading.Lock()                    # For synchronizing sending operations
        self.wait_cond = threading.Condition(self.recv_lock) # To signal state changes

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        # Internal state for in-order delivery and sequence numbers.
        # For both sender and receiver:
        self.window = {
            "last_ack": 0,            # For sender: highest cumulative ack received (LAR)
            "next_seq_to_send": 0,    # For sender: next sequence number to assign (LFS)
            "recv_buf": b"",          # For receiver: data buffer for in-order delivered data
            "recv_len": 0,            # For receiver: current size of recv_buf
        }

        self.sock_type = None
        self.conn = None
        self.my_port = None

        # RTT estimation variables (already implemented)
        self.estimated_rtt = DEFAULT_TIMEOUT / 2  
        self.timeout = 2 * self.estimated_rtt       
        self.alpha = 0.5                            

        # Sliding window variables for sender:
        self.sender_window_size = WINDOW_SIZE  # Maximum bytes the sender can have outstanding
        # The receiver's advertised window (in bytes); initially, the receiver can accept up to MAX_NETWORK_BUFFER.
        self.advertised_window = MAX_NETWORK_BUFFER

        # Dictionary to hold unacknowledged segments:
        # Keys are the segment's starting sequence number; values are tuples (segment, send_time, payload_length)
        self.unacked_segments = {}

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

        # Start the backend thread to handle incoming packets
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

        # Blocking read: wait until there is data available
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    self.wait_cond.wait()

        with self.recv_lock:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]
                    # Remove data from the buffer after reading
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
        Send 'data' by splitting it into MSS-sized segments while enforcing a sliding window:
          - The sender will not have more than min(sender_window_size, advertised_window) bytes outstanding.
          - Each segment is timed and retransmitted if an ACK is not received within the current timeout.
        """
        offset = 0
        total_len = len(data)

        # Main loop: continue until all data has been sent and acknowledged.
        while offset < total_len or self.unacked_segments:
            # Send new segments while window space is available.
            with self.send_lock:
                # Calculate outstanding bytes (bytes sent but not yet acknowledged)
                outstanding = self.window["next_seq_to_send"] - self.window["last_ack"]
                # Determine the allowed window size (the sender's limit and what the receiver can accept)
                allowed_window = min(self.sender_window_size, self.advertised_window)
                while offset < total_len and outstanding < allowed_window:
                    payload_len = min(MSS, total_len - offset)
                    seq_no = self.window["next_seq_to_send"]
                    chunk = data[offset: offset + payload_len]
                    # Create data packet (flags=0 for data)
                    segment = Packet(seq=seq_no, ack=0, flags=0, payload=chunk, win=0)
                    # Send the segment
                    self.sock_fd.sendto(segment.encode(), self.conn)
                    # Record the segment for possible retransmission
                    with self.wait_cond:
                        self.unacked_segments[seq_no] = (segment, time.time(), payload_len)
                    self.window["next_seq_to_send"] += payload_len
                    offset += payload_len
                    outstanding = self.window["next_seq_to_send"] - self.window["last_ack"]
                    print(f"Sent segment: seq={seq_no}, len={payload_len}, outstanding={outstanding}")
            
            # Wait a short period (or until notified by ACK arrival)
            with self.wait_cond:
                self.wait_cond.wait(timeout=0.1)
            
            # Check for timeouts and retransmit segments if needed.
            current_time = time.time()
            with self.wait_cond:
                for seq, (segment, send_time, seg_len) in list(self.unacked_segments.items()):
                    if current_time - send_time >= self.timeout:
                        print(f"Timeout: Retransmitting segment with seq={seq}")
                        self.sock_fd.sendto(segment.encode(), self.conn)
                        # Update the send time for this segment.
                        self.unacked_segments[seq] = (segment, current_time, seg_len)

    def backend(self):
        """
        Backend loop to handle incoming packets (both ACKs and data).
        This thread is solely responsible for reading from the socket.
        """
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)
                
                # For a listener, establish connection on first packet
                if self.conn is None:
                    self.conn = addr

                # If this is an ACK packet, handle sender-side updates.
                if (packet.flags & ACK_FLAG) != 0:
                    with self.wait_cond:
                        if packet.ack > self.window["last_ack"]:
                            self.window["last_ack"] = packet.ack
                        # Update the advertised window from the receiver's ACK.
                        self.advertised_window = packet.win
                        # Remove all segments that are now acknowledged.
                        for seq in list(self.unacked_segments.keys()):
                            if seq < packet.ack:
                                del self.unacked_segments[seq]
                        self.wait_cond.notify_all()
                    print(f"Received ACK: ack={packet.ack}, advertised_window={packet.win}")
                    continue

                # Otherwise, assume it is a data packet.
                # Only accept the packet if it is the expected one (in-order delivery).
                if packet.seq == self.window["last_ack"]:
                    with self.recv_lock:
                        # Enforce that the receive buffer does not exceed MAX_NETWORK_BUFFER.
                        if self.window["recv_len"] + len(packet.payload) > MAX_NETWORK_BUFFER:
                            print("Receive buffer full. Dropping packet.")
                            # Advertise current available window (which will be 0 or small)
                            available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG, win=available)
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                        else:
                            self.window["recv_buf"] += packet.payload
                            self.window["recv_len"] += len(packet.payload)
                            with self.wait_cond:
                                self.wait_cond.notify_all()
                            print(f"Received segment: seq={packet.seq}, len={len(packet.payload)}")
                            # Compute new cumulative ack and the receiver's available window.
                            ack_val = packet.seq + len(packet.payload)
                            available = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(seq=0, ack=ack_val, flags=ACK_FLAG, win=available)
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            # Advance expected sequence number
                            self.window["last_ack"] = ack_val
                else:
                    # Out-of-order packet (not accepted in this basic implementation)
                    print(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")

            except socket.timeout:
                continue
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")
