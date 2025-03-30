import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER
from typing import List

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

# the FSM states
LISTEN = 0
SYN_SENT = 1
SYN_RCVD = 2
ESTABLISHED = 3
FIN_SENT = 4
CLOSE_WAIT = 5
TIME_WAIT = 6
LAST_ACK = 7

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b"", window_size=MAX_NETWORK_BUFFER):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload
        self.window_size = window_size

    def encode(self):
        # Encode the packet header and payload into bytes
        header = struct.pack("!IIIHI", self.seq, self.ack, self.flags, len(self.payload), self.window_size)
        return header + self.payload

    def next_packet_seq(self):
        return self.seq + len(self.payload)

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIIHI")
        seq, ack, flags, payload_len, window_size = struct.unpack("!IIIHI", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, payload, window_size)


class TransportSocket:
    def __init__(self):
        self.sock_fd = None

        # set up variables for estimating the round trip time
        self.estimate_rtt = 0.1
        self.alpha = 0.85
        self.timeout = 2 * self.estimate_rtt

        # buffer that stores the out-of-order packets
        self.buffer = []

        # check for repeats
        self.repeated_ack = 0

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
            "status": LISTEN,
            'send_window': MAX_NETWORK_BUFFER
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None

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

    def connect(self):
        """
        Client-side initialization of the 3 way handshake (send a SYN, and wait for SYN-ACK from the server)
        """
        # step 1: send SYN packet
        seq_no = self.window["next_seq_to_send"]
        syn_packet = Packet(seq=seq_no, ack=0, flags=SYN_FLAG)

        self.window['status'] = SYN_SENT

        while True:
            self.sock_fd.sendto(syn_packet.encode(), self.conn)
            print(f"Sent SYN, seq={seq_no}")

            if self.wait_for_ack(seq_no + 1):
                break
            else:
                print(f"Retransmitting SYN, seq={seq_no}")

        self.window["next_seq_to_send"] = self.window['next_seg_expected']

        if self.window['status'] == SYN_RCVD:
            seq_no = self.window["next_seq_to_send"]
            syn_packet = Packet(seq=seq_no, ack=self.window['last_ack'], flags=SYN_FLAG + ACK_FLAG)
            while True:
                self.sock_fd.sendto(syn_packet.encode(), self.conn)
                print(f"Sent SYN+ACK, seq={seq_no}")

                if self.wait_for_ack(seq_no + 1):
                    break
                else:
                    print(f"Retransmitting SYN+ACK, seq={seq_no}")

        if self.window['status'] == ESTABLISHED:
            seq_no = self.window["next_seq_to_send"]
            syn_packet = Packet(seq=0, ack=self.window['last_ack'], flags=SYN_FLAG + ACK_FLAG)
            self.sock_fd.sendto(syn_packet.encode(), self.conn)
            print(f"Sent SYN+ACK, seq={seq_no}")


        # Send ACK to complete the handshake
        seq_num = self.window['next_seq_to_send']
        ack_val = packet.seq + 1
        ack_packet = Packet(seq=seq_num, ack=ack_val, flags=ACK_FLAG)
        self.sock_fd.sendto(ack_packet.encode(), addr)

        # update the last ack that we sent out
        self.window['last_ack'] = ack_val
        print(f"Sent ACK, ack={ack_val}")
        # Connection is now established
        self.conn = addr  # Mark the connection as established

        self.wait_cond.notify_all()


    @staticmethod
    def ack_goal(unacked_packets: List[Packet]):
        return unacked_packets[0].next_packet_seq()

    def used_window_size(self, unacked_packets: List[Packet]):
        if not unacked_packets:
            return 0
        return unacked_packets[-1].next_packet_seq() - self.window['next_seq_expected']

    def send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and reliably wait for each ACK
        """
        # check if we have established connection yet
        if self.window['status'] == LISTEN:
            self.connect()

        offset = 0
        total_len = len(data)

        # store the timestamp for the first sent packet (this will be the packet we track for timeouts)
        first_sent_time = None

        # keep track of the unacknowledged packets
        unacked_packets = []

        # While there's data left to send
        while offset < total_len:
            payload_len = min(MSS, total_len - offset)

            # if we are able to send another packet
            if self.used_window_size(unacked_packets) + payload_len < self.window['send_window']:

                # Current sequence number
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset : offset + payload_len]

                # Create a packet
                segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, payload=chunk)

                print(f"Sending segment (seq={seq_no}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)

                # record the time the first packet was sent
                if first_sent_time is None:
                    first_sent_time = time.time()

                self.window['next_seq_to_send'] += payload_len

                # add the packet to the send window
                unacked_packets.append(segment)
            else:
                # no other packets can be sent, start waiting
                with self.recv_lock:
                    while self.window["next_seq_expected"] < self.ack_goal(unacked_packets):
                        elapsed = time.time() - first_sent_time
                        remaining = DEFAULT_TIMEOUT - elapsed
                        if remaining <= 0:
                            # restart the timer and resend the first packet
                            first_sent_time = time.time()
                            print("Timeout expired. Resending first unacknowledged packet.")
                            self.sock_fd.sendto(unacked_packets[0].encode(), self.conn)
                            self.repeated_ack = 0

                        self.wait_cond.wait(timeout=remaining)

            # now check about the acknowledgement of the first ack
            if self.window["next_seq_expected"] >= self.ack_goal(unacked_packets):
                # check what segments have been acked then
                acked_segments = [p for p in unacked_packets if p.next_packet_seq() <= self.window["next_seq_expected"]]
                print(f"Up to segment {acked_segments[-1].seq} have been acknowledged.")
                # remove these from the list
                unacked_packets = unacked_packets[len(acked_segments):]

                # set the repeated ack to zero
                self.repeated_ack = 0

                # if there are still unacknowledged packets, reset the timer for the first one
                if unacked_packets:
                    first_sent_time = time.time()

                continue

            # timeout handling by checking if the timer has expired for the first sent packet
            current_time = time.time()
            if first_sent_time and (current_time - first_sent_time > self.timeout):
                print("Timeout expired. Resending first unacknowledged packet.")
                # Resend the first unacknowledged packet
                self.sock_fd.sendto(unacked_packets[0].encode(), self.conn)

                # Reset the timestamp (since we're retransmitting)
                first_sent_time = current_time

            # check if there was 3 repeated ACKs
            if self.repeated_ack > 3:
                self.sock_fd.sendto(unacked_packets[0].encode(), self.conn)

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

                self.wait_cond.wait(timeout=remaining)

            return True

    def seq_falls_within_window(self, packet):
        return self.window['next_seq_expected'] + self.window['send_window'] > packet.seq > self.window["next_seq_expected"]

    def backend(self):
        """
        Backend loop to handle receiving data and sending acknowledgments.
        All incoming packets are read in this thread only, to avoid concurrency conflicts.
        """
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr

                if self.window['status'] == LISTEN:
                    if packet.flags & SYN_FLAG != 0:
                        with self.recv_lock:
                            print(f"Received SYN, seq={packet.seq}, sending SYN-ACK")
                            self.window['status'] = SYN_RCVD

                            ack_val = packet.seq
                            syn_ack_packet = Packet(seq=0, ack=ack_val, flags=SYN_FLAG + ACK_FLAG)
                            self.sock_fd.sendto(syn_ack_packet.encode(), addr)
                            print('[SYN-ACK] sent')
                            self.window['last_ack'] = ack_val

                            self.wait_cond.notify_all()
                        continue

                elif self.window['status'] == SYN_SENT:
                    # If it's a SYN-ACK packet (client received SYN-ACK, completing handshake)
                    if packet.flags and (SYN_FLAG + ACK_FLAG) != 0:
                        with self.recv_lock:
                            if packet.ack > self.window["next_seq_expected"]:
                                print(f"Received SYN-ACK, ack={packet.ack}")
                                self.window["next_seq_expected"] = packet.ack
                                # update the status
                                self.window['status'] = ESTABLISHED
                            self.wait_cond.notify_all()
                        continue

                    elif packet.flags & SYN_FLAG != 0:
                        with self.recv_lock:
                            if packet.ack > self.window["next_seq_expected"]:
                                print(f"Received SYN, ack={packet.ack}")
                                self.window["next_seq_expected"] = packet.ack
                                # update the status
                                self.window['status'] = SYN_RCVD
                            self.wait_cond.notify_all()
                        continue

                elif self.window['status'] == SYN_RCVD:
                    with self.recv_lock:
                        if packet.flags == ACK_FLAG:
                            print(f"Received ACK for the SYN+ACK, ack={packet.ack}")
                            self.window['next_seq_expected'] = packet.ack
                            # update the status
                            self.window['status'] = ESTABLISHED
                        self.wait_cond.notify_all()
                    continue

                elif self.window['status'] == ESTABLISHED:
                    # If it's an ACK packet, update our sending side
                    if (packet.flags & ACK_FLAG) != 0:
                        with self.recv_lock:
                            if packet.ack > self.window["next_seq_expected"]:
                                self.window["next_seq_expected"] = packet.ack
                                self.repeated_ack = 1
                            # check if this is a repeat
                            if packet.ack == self.window['next_seq_expected']:
                                self.repeated_ack += 1
                            self.wait_cond.notify_all()
                        continue

                    # Otherwise, assume it is a data packet
                    # Check if the sequence matches our 'last_ack' (in-order data)
                    if packet.seq == self.window["last_ack"]:
                        self.buffer.append(packet)
                        # order buffer based on sequence numbers so that we can know which ones to put up
                        self.buffer = sorted(self.buffer, key=lambda p: p.seq)
                        # check how many are in order
                        index = 1
                        next_seq = self.buffer[0].next_packet_seq()
                        while len(self.buffer) <= index and self.buffer[index].seq == next_seq:
                            next_seq = self.buffer[index].next_packet_seq()
                            index += 1
                        packets_to_add = self.buffer[:index]
                        self.buffer = self.buffer[index:]

                        with self.recv_lock:
                            # Append payload to our receive buffer
                            for p in packets_to_add:
                                self.window["recv_buf"] += p.payload
                                self.window["recv_len"] += len(p.payload)

                        with self.wait_cond:
                            self.wait_cond.notify_all()

                        print(f"Received segment {packet.seq} with {len(packet.payload)} bytes.")

                        # Send back an acknowledgment
                        last_ack = packets_to_add[-1].next_packet_seq()
                        ack_packet = Packet(seq=0, ack=last_ack, flags=ACK_FLAG)
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        # Update last_ack
                        self.window["last_ack"] = last_ack

                    elif self.seq_falls_within_window(packet):
                        # add out of order to the buffer (but make sure it still falls within the window frame
                        # check that this sequence number is not already here
                        if not any(d.seq == packet.seq for d in self.buffer):
                            self.buffer.append(packet)
                            print(f"Out-of-order packet: seq={packet.seq} again, expected={self.window['next_seq_expected']}")
                        else:
                            print(f"Out-of-order packet: seq={packet.seq} received again, expected={self.window['next_seq_expected']}")

                elif self.window['status'] == FIN_SENT:
                    pass

                elif self.window['status'] == CLOSE_WAIT:
                    pass

                elif self.window['status'] == TIME_WAIT:
                    pass

                elif self.window['status'] == LAST_ACK:
                    pass

            except socket.timeout:
                continue
        
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")
