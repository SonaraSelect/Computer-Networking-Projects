#!/usr/bin/env python3

import sys
import socket
import select
import time
import re
import xml.etree.ElementTree as ET

################################################################################
# Global / Config Variables
################################################################################

# Where to connect for the backend DASH server
BACKEND_IP = "149.165.170.233"
BACKEND_PORT = 80

# The local port on which this proxy listens
LISTEN_PORT = 8888

# EWMA alpha for throughput updates
ALPHA = 0.2

# Our current estimated throughput (Kbps)
current_throughput = 0.0

# List of available bitrates parsed from the real manifest (in Kbps)
available_bitrates = []

# If the user requests "manifest.mpd", we actually fetch the real one from the server
# (to parse bitrates), but serve "manifest_nolist.mpd" back to the client.
# Provide your local path to a "manifest_nolist.mpd" if you have it locally:
MANIFEST_NOLIST_PATH = "manifest_nolist.mpd"

# Regex to match chunk requests like:  GET /1000Seg2.m4s ...
CHUNK_REQUEST_REGEX = re.compile(r"GET\s+/(?P<bitrate>\d+)(?P<rest>Seg\d+.*?)\sHTTP")

################################################################################
# Helper Functions
################################################################################

def fetch_real_manifest_and_parse_bitrates():
    """
    Fetch the real manifest.mpd from the backend server once,
    parse out the available bitrates, and store them in a global list.
    """
    global available_bitrates

    # Build a simple HTTP GET request
    request = (
        "GET /manifest.mpd HTTP/1.0\r\n"
        f"Host: {BACKEND_IP}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    # Connect to server and send request
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((BACKEND_IP, BACKEND_PORT))
    s.sendall(request.encode("utf-8"))

    # Read response
    response_data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        response_data += chunk
    s.close()

    # Separate headers and body
    # (Assumes no chunked encoding, and a well-formed response)
    sep = response_data.find(b"\r\n\r\n")
    if sep == -1:
        return  # can't parse if no header/body separation

    body = response_data[sep+4:]  # skip the \r\n\r\n
    # Parse the XML to find <Representation ... bandwidth="..."/>
    try:
        root = ET.fromstring(body)
        # In many DASH MPDs, the Representation elements are under:
        # <MPD><Period><AdaptationSet><Representation ... bandwidth="xxx" />
        # You may need to adjust the path if your MPD structure is different.
        reps = root.findall(".//{*}Representation")
        bitrates = []
        for r in reps:
            bw = r.get("bandwidth")
            if bw is not None:
                bw_kbps = int(bw) // 1000  # convert to Kbps from bps
                bitrates.append(bw_kbps)
        bitrates.sort()
        available_bitrates = bitrates
        print(f"[INFO] Parsed bitrates: {available_bitrates}")
    except ET.ParseError as e:
        print("[ERROR] Could not parse MPD XML:", e)


def pick_bitrate_for_throughput(tput_kbps):
    """
    Given the current throughput estimate, pick the highest
    bitrate such that tput >= 1.5 * that_bitrate.
    If none qualify, pick the lowest.
    """
    if not available_bitrates:
        return 1000  # fallback if we haven't parsed anything

    # Sort ascending
    for br in reversed(available_bitrates):
        if tput_kbps >= 1.5 * br:
            return br
    # If we get here, none satisfy, pick the lowest
    return available_bitrates[0]


def update_throughput_ewma(chunk_size_bytes, duration_s):
    """
    Given a chunk size in bytes and the time (in seconds) it took to download,
    compute throughput in Kbps, update the global EWMA.
    """
    global current_throughput

    # Convert chunk size to bits, then bits/sec -> Kbps
    chunk_size_bits = chunk_size_bytes * 8
    if duration_s <= 0:
        return  # avoid divide-by-zero
    inst_tput = (chunk_size_bits / duration_s) / 1000.0  # Kbps

    if current_throughput <= 0:
        # If first measurement, just set it
        current_throughput = inst_tput
    else:
        # EWMA update
        current_throughput = ALPHA * inst_tput + (1 - ALPHA) * current_throughput

    return inst_tput


def log_request(duration, inst_tput, avg_tput, bitrate, chunkname):
    """
    Log activity in the requested format:
      <time> <duration> <tput> <avg-tput> <bitrate> <chunkname>
    """
    now = time.time()
    print(f"{now:.3f} {duration:.3f} {inst_tput:.3f} {avg_tput:.3f} {bitrate} {chunkname}")


################################################################################
# Epoll-based Proxy
################################################################################

class ProxyConnection:
    """
    Holds state for a single client connection + the backend server connection.
    """
    def __init__(self, client_sock, epoll):
        self.client_sock = client_sock
        self.client_addr = client_sock.getpeername()
        self.server_sock = None

        self.client_buffer = b""
        self.server_buffer = b""

        # For measuring chunk downloads
        self.download_start_time = None
        self.content_length = 0
        self.received_bytes = 0
        self.current_bitrate = 0
        self.chunk_name = ""

        # Register for reading client requests
        self.fd_client = client_sock.fileno()
        epoll.register(self.fd_client, select.EPOLLIN)

        # We'll lazily connect to the server when we have the first request
        # (or on each request if you prefer).
        # We'll also store an epoll reference to modify events easily.
        self.epoll = epoll

    def handle_client_readable(self):
        """
        Called by the main loop when the client socket is readable.
        We read data, parse requests, handle rewriting, and connect/send
        to the server as needed.
        """
        try:
            data = self.client_sock.recv(4096)
        except ConnectionError:
            self.close()
            return

        if not data:
            # Client closed
            self.close()
            return

        self.client_buffer += data

        # Attempt to parse full HTTP requests from client_buffer.
        # For simplicity, we'll assume one request at a time (no pipelining).
        # Real pipelining requires a more robust parser.
        if b"\r\n\r\n" not in self.client_buffer:
            # Not a complete request yet
            return

        # Separate request header from possible body (rare in GET)
        header_end = self.client_buffer.find(b"\r\n\r\n")
        request_header = self.client_buffer[:header_end].decode("utf-8", errors="replace")
        self.client_buffer = self.client_buffer[header_end+4:]  # remove from buffer

        # If needed, parse Content-Length for POST, etc. (not typical for this scenario).
        # We'll ignore that for now.

        # We have the request line and headers in request_header
        lines = request_header.split("\r\n")
        request_line = lines[0]
        # Example: GET /1000Seg2.m4s HTTP/1.1

        # 1) Check if it's a manifest request
        if "GET /manifest.mpd" in request_line:
            # Make sure we have the real manifest bitrates
            if not available_bitrates:
                fetch_real_manifest_and_parse_bitrates()

            # Instead of fetching from server for the client, we serve manifest_nolist.mpd
            self.serve_local_manifest_nolist()
            return

        # 2) Check if it's a chunk request
        match = CHUNK_REQUEST_REGEX.search(request_line)
        if match:
            original_bitrate = int(match.group("bitrate"))
            rest = match.group("rest")  # e.g. Seg2.m4s
            # Decide new bitrate
            chosen_bitrate = pick_bitrate_for_throughput(current_throughput)
            new_request_line = f"GET /{chosen_bitrate}{rest} HTTP/1.1"

            # We'll store for logging
            self.current_bitrate = chosen_bitrate
            self.chunk_name = f"{chosen_bitrate}{rest}"

            # Rebuild the entire request with the new request line
            new_header_lines = [new_request_line] + lines[1:]
            new_request_header = "\r\n".join(new_header_lines) + "\r\n\r\n"
            self.forward_to_server(new_request_header.encode("utf-8"))
            return

        # 3) If some other request, just forward as-is
        self.forward_to_server(request_header.encode("utf-8") + b"\r\n\r\n")

    def serve_local_manifest_nolist(self):
        """
        Sends the local manifest_nolist.mpd file back to the client.
        """
        try:
            with open(MANIFEST_NOLIST_PATH, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            # If we don't have a local file, just send 404
            resp = (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.client_sock.sendall(resp.encode("utf-8"))
            return

        # Send a 200 OK with the file
        resp = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: application/dash+xml\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8") + body

        self.client_sock.sendall(resp)

    def forward_to_server(self, request_data):
        """
        Connect to the backend server if not connected, then send request_data.
        """
        if self.server_sock is None:
            try:
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setblocking(False)
                self.server_sock.connect_ex((BACKEND_IP, BACKEND_PORT))
                # Register server socket in epoll
                self.fd_server = self.server_sock.fileno()
                self.epoll.register(self.fd_server, select.EPOLLIN)
            except Exception as e:
                print("[ERROR] Server connection failed:", e)
                self.close()
                return

        # (Re)initialize counters for chunk throughput measurement
        self.download_start_time = time.time()
        self.content_length = 0
        self.received_bytes = 0

        try:
            self.server_sock.sendall(request_data)
        except ConnectionError:
            self.close()

    def handle_server_readable(self):
        """
        Called when the server socket has data for us.
        We read it, measure throughput if the response completes, and forward to client.
        """
        try:
            data = self.server_sock.recv(4096)
        except ConnectionError:
            self.close()
            return

        if not data:
            # Server closed
            self.close()
            return

        # Accumulate for throughput measurement
        self.received_bytes += len(data)

        # Check if we have not yet parsed Content-Length from the response header
        # to know the total chunk size. For a simple approach, we can parse once
        # the headers are in. We do a quick hack: look for the first \r\n\r\n in data
        # if we haven't read any bytes yet.
        if self.content_length == 0:
            # We might have partial header + partial body, so let's accumulate in a buffer.
            self.server_buffer += data
            # Try to find the header boundary
            header_end = self.server_buffer.find(b"\r\n\r\n")
            if header_end != -1:
                # parse headers
                header_part = self.server_buffer[:header_end].decode("utf-8", errors="replace")
                # look for Content-Length
                for line in header_part.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            self.content_length = int(line.split(":")[1].strip())
                        except ValueError:
                            self.content_length = 0
                # The rest is body
                body_part = self.server_buffer[header_end+4:]
                self.received_bytes = len(body_part)
                # Now forward everything to the client
                self.client_sock.sendall(self.server_buffer)
                self.server_buffer = b""
            # else: we still haven't got the full header, just wait
        else:
            # We already know content_length, so just forward data
            self.client_sock.sendall(data)

        # Check if we have the entire chunk
        if self.content_length > 0 and self.received_bytes >= self.content_length:
            # We can measure the time it took
            duration = time.time() - self.download_start_time
            inst_tput = update_throughput_ewma(self.received_bytes, duration)
            avg_tput = current_throughput
            # Log
            if self.chunk_name:
                log_request(duration, inst_tput, avg_tput, self.current_bitrate, self.chunk_name)

            # Reset counters for the next chunk
            self.download_start_time = None
            self.content_length = 0
            self.received_bytes = 0
            self.chunk_name = ""

    def close(self):
        """
        Cleanup sockets and epoll registrations.
        """
        # Unregister and close client
        if self.client_sock:
            try:
                self.epoll.unregister(self.client_sock.fileno())
            except:
                pass
            self.client_sock.close()
            self.client_sock = None

        # Unregister and close server
        if self.server_sock:
            try:
                self.epoll.unregister(self.server_sock.fileno())
            except:
                pass
            self.server_sock.close()
            self.server_sock = None


def run_proxy_server():
    """
    Main entry point: sets up a listening socket and uses epoll to handle events.
    """
    # Create a TCP socket to listen for incoming client connections
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("", LISTEN_PORT))
    listen_sock.listen(100)
    listen_sock.setblocking(False)

    # Create epoll object
    ep = select.epoll()
    # Register the listening socket for read events
    ep.register(listen_sock.fileno(), select.EPOLLIN)

    # Map file descriptors to ProxyConnection or to the listen socket
    fd_to_connection = {}

    print(f"[INFO] Proxy listening on port {LISTEN_PORT}...")

    try:
        while True:
            events = ep.poll(1)  # 1-second timeout (adjust as needed)
            for fd, event in events:
                if fd == listen_sock.fileno():
                    # A new client is connecting
                    client_sock, addr = listen_sock.accept()
                    client_sock.setblocking(False)
                    # Create a ProxyConnection to handle it
                    conn = ProxyConnection(client_sock, ep)
                    fd_to_connection[client_sock.fileno()] = conn
                    print(f"[INFO] New client {addr}")
                else:
                    # Must be a client or server socket
                    conn = fd_to_connection.get(fd)
                    if conn is None:
                        continue

                    # Check if it's the client socket or the server socket
                    if conn.client_sock and fd == conn.client_sock.fileno():
                        # Something to read from client
                        if event & select.EPOLLIN:
                            conn.handle_client_readable()
                        if event & (select.EPOLLHUP | select.EPOLLERR):
                            conn.close()
                            del fd_to_connection[fd]
                    elif conn.server_sock and fd == conn.server_sock.fileno():
                        # Something to read from server
                        if event & select.EPOLLIN:
                            conn.handle_server_readable()
                        if event & (select.EPOLLHUP | select.EPOLLERR):
                            conn.close()
                            del fd_to_connection[fd]
                    else:
                        # Unknown? Just close
                        conn.close()
                        fd_to_connection.pop(fd, None)
    finally:
        ep.close()
        listen_sock.close()


if __name__ == "__main__":
    # Optional: parse command-line args for ALPHA, LISTEN_PORT, etc.
    # e.g. python proxy.py <alpha> <listen_port>
    if len(sys.argv) >= 2:
        ALPHA = float(sys.argv[1])
    if len(sys.argv) >= 3:
        LISTEN_PORT = int(sys.argv[2])

    run_proxy_server()
