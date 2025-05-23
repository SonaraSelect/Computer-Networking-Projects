#!/usr/bin/env python3 

import sys
import socket
import select
import time
import re

HOST_SERVER = "149.165.170.233"
HOST_PORT = 80
DEFAULT_PORT = 9000

# Global throughput tracking IN BYTES/SEC (converts later)
global_avg_throughpyt = 0.0  
remote_last_time = {}  # { fd: last_timestamp }
global_alpha = 0.5     # default alpha

# Log file to be set on initialization
log_file_handle = None

# Global start time of epoll
epoll_start_time = None

# Dictionary to track segment requests, keyed by remote socket FD.
# Each entry contains:
#   'start_time': when the GET was received,
#   'header_buffer': to hold HTTP headers,
#   'header_parsed': flag indicating header completion,
#   'expected_length': Content-Length from the response,
#   'bytes_received': accumulated body bytes,
#   'bitrate': parsed from the URL,
#   'chunkname': parsed from the URL,
#   'logged': flag to ensure we log only once.
segment_requests = {}

def main():
    global global_alpha, global_avg_throughpyt, log_file_handle, epoll_start_time

    # python3 proxy.py <log-file> <alpha> [<port>]
    if len(sys.argv) < 2:
        print("Usage: python3 proxy.py <log-file> <alpha> [<port>]")
        sys.exit(1)

    # 1) Log file path
    log_file_path = sys.argv[1]

    # 2) Alpha
    try:
        alpha_arg = float(sys.argv[2])
        global_alpha = alpha_arg
    except (IndexError, ValueError):
        print("Invalid or missing alpha value; using default 0.5")
        global_alpha = 0.5

    # 3) Port argument
    listen_port = DEFAULT_PORT
    if len(sys.argv) >= 4:
        listen_port = int(sys.argv[3])

    # Open log file for writing
    try:
        log_file_handle = open(log_file_path, "w")
    except Exception as e:
        print(f"Error opening log file '{log_file_path}': {e}")
        sys.exit(1)

    print(f"Starting proxy on port {listen_port}, forwarding to {HOST_SERVER}:{HOST_PORT}")
    print(f"Using ALPHA = {global_alpha} for throughput smoothing")
    print(f"Logging final segment info to: {log_file_path}")

    # Create non-blocking server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", listen_port))
    server_sock.listen()
    server_sock.setblocking(False)

    # Create epoll object
    epoll = select.epoll()

    # Record start time for epoll events.
    epoll_start_time = time.time()

    # Register server socket for incoming connections
    epoll.register(server_sock.fileno(), select.EPOLLIN)

    # Mappings:
    #   fd_to_socket: fd -> socket object
    #   fd_to_buffer: fd -> outgoing data buffer (bytes)
    #   fd_group:     fd -> group fd (client <--> remote)
    #   fd_role:      fd -> 'client' or 'remote'
    fd_to_socket = {server_sock.fileno(): server_sock}
    fd_to_buffer = {}
    fd_group   = {}
    fd_role      = {}

    try:
        while True:
            events = epoll.poll(timeout=1)
            for fd, event in events:
                # Accept new client connection
                if fd == server_sock.fileno():
                    client_sock, addr = server_sock.accept()
                    client_sock.setblocking(False)
                    print(f"Accepted connection from {addr}")

                    epoll.register(client_sock.fileno(), select.EPOLLIN)
                    fd_to_socket[client_sock.fileno()] = client_sock
                    fd_to_buffer[client_sock.fileno()] = b""
                    fd_role[client_sock.fileno()] = 'client'

                    # Make a socket that connects to hosting server
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.setblocking(False)
                    try:
                        remote_sock.connect((HOST_SERVER, HOST_PORT))
                    except BlockingIOError:
                        pass  # Non-blocking connection is in progress

                    epoll.register(remote_sock.fileno(), select.EPOLLIN | select.EPOLLOUT)
                    fd_to_socket[remote_sock.fileno()] = remote_sock
                    fd_to_buffer[remote_sock.fileno()] = b""
                    fd_role[remote_sock.fileno()] = 'remote'

                    # Start throughput measurement
                    remote_last_time[remote_sock.fileno()] = time.time()

                    # Cross-reference the group file descriptors
                    fd_group[client_sock.fileno()] = remote_sock.fileno()
                    fd_group[remote_sock.fileno()] = client_sock.fileno()

                else:
                    sock = fd_to_socket[fd]
                    group_fd = fd_group.get(fd)

                    if event & select.EPOLLIN:
                        try:
                            data = sock.recv(4096)
                            if data:
                                if fd_role.get(fd) == 'client':
                                    # Process client GET requests; analyze segment and intercept manifest
                                    data = handle_client_data(data, fd, fd_group)
                                elif fd_role.get(fd) == 'remote':
                                    # Update throughput measurements
                                    now = time.time()
                                    last_time = remote_last_time.get(fd, now)
                                    dt = now - last_time
                                    if dt > 0:
                                        measured = len(data) / dt  # IN BYTES/SEC -- will be converted later!!
                                        global_avg_throughpyt = (
                                            global_alpha * measured +
                                            (1 - global_alpha) * global_avg_throughpyt
                                        )
                                    remote_last_time[fd] = now

                                    if fd in segment_requests:
                                        process_segment_data(fd, data, now)
                                # Forward (possibly modified) data to the groupmember.
                                fd_to_buffer[group_fd] += data
                                epoll.modify(group_fd, select.EPOLLIN | select.EPOLLOUT)
                            else:
                                close_connection(epoll, fd, fd_group, fd_to_socket, fd_to_buffer, fd_role)
                        except ConnectionResetError:
                            close_connection(epoll, fd, fd_group, fd_to_socket, fd_to_buffer, fd_role)

                    if event & select.EPOLLOUT:
                        if fd_to_buffer[fd]:
                            try:
                                sent = sock.send(fd_to_buffer[fd])
                                fd_to_buffer[fd] = fd_to_buffer[fd][sent:]
                            except ConnectionResetError:
                                close_connection(epoll, fd, fd_group, fd_to_socket, fd_to_buffer, fd_role)
                                continue
                        if not fd_to_buffer[fd]:
                            epoll.modify(fd, select.EPOLLIN)

                    if event & (select.EPOLLHUP | select.EPOLLERR):
                        close_connection(epoll, fd, fd_group, fd_to_socket, fd_to_buffer, fd_role)
    finally:
        epoll.unregister(server_sock.fileno())
        epoll.close()
        server_sock.close()
        if log_file_handle:
            log_file_handle.close()

def handle_client_data(data_chunk, client_fd, fd_group):
    """
    Search client requests for manifest file or segment data
    """
    lines = data_chunk.split(b"\r\n")
    new_lines = []
    for line in lines:
        if line.startswith(b"GET "):
            parts = line.split()
            if len(parts) >= 2:
                url = parts[1].decode('utf-8', errors='replace')
                print(f"GET request URL: {url}")
                if 'manifest.mpd' in url:
                    new_url = url.replace('manifest.mpd', 'manifest_nolist.mpd')
                    parts[1] = new_url.encode('utf-8')
                    line = b' '.join(parts)
                    print(f"[INFO] Replacing manifest request with: {new_url}")
                else:
                    # Rip chunk name from last bit of URL for segment request
                    stripped = url.lstrip('/')
                    last_part = stripped.rsplit('/', 1)[-1]  # Extracts "500seg1"
                    m = re.match(r"(\d+)(.+)", last_part)
                    if m:
                        bitrate = m.group(1)
                        chunkname = last_part
                        remote_fd = fd_group.get(client_fd)
                        if remote_fd is not None:
                            segment_requests[remote_fd] = {
                                'start_time': time.time(),
                                'header_buffer': b"",
                                'header_parsed': False,
                                'expected_length': None,
                                'bytes_received': 0,
                                'bitrate': bitrate,
                                'chunkname': chunkname,
                                'logged': False
                            }
                    else:
                        print("[WARN] Could not parse segment info from URL.")
        new_lines.append(line)
    return b"\r\n".join(new_lines)

def process_segment_data(remote_fd, data, now):
    """
    Parse GET requests for Segment to mark when to measure and mark appropriate data for log
    """
    global segment_requests, global_avg_throughpyt, log_file_handle, epoll_start_time
    seg = segment_requests[remote_fd]

    if not seg['header_parsed']:
        seg['header_buffer'] += data
        if b"\r\n\r\n" in seg['header_buffer']:
            header, body = seg['header_buffer'].split(b"\r\n\r\n", 1)
            seg['header_parsed'] = True
            seg['bytes_received'] += len(body)
            # Extract Content-Length if we can
            for line in header.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    try:
                        seg['expected_length'] = int(line.split(b":")[1].strip())
                    except Exception as e:
                        print(f"[WARN] Failed to parse Content-Length: {e}")
    else:
        seg['bytes_received'] += len(data)

    if (seg['expected_length'] is not None and 
        seg['bytes_received'] >= seg['expected_length'] and 
        not seg['logged']):
        duration = now - seg['start_time']
        current_throughput = seg['bytes_received'] / duration if duration > 0 else 0.0

        # Convert throughput values to Kbps from Bps
        current_throughput_kbps = current_throughput * 8 / 1000
        avg_throughput_kbps = global_avg_throughpyt * 8 / 1000

        time_since_epoll = now - epoll_start_time

        log_line = (
            f"{time_since_epoll:.3f} "  # seconds since epoll started
            f"{duration:.3f} "          # duration of chunk download
            f"{current_throughput_kbps:.3f} "  # current throughput in (kbps)
            f"{avg_throughput_kbps:.3f} "  # average throughput in (kbps)
            f"{seg['bitrate']} "
            f"{seg['chunkname']}\n"
        )

        log_file_handle.write(log_line)
        log_file_handle.flush()

        seg['logged'] = True

def close_connection(epoll, fd, fd_group, fd_to_socket, fd_to_buffer, fd_role):
    if fd in fd_group:
        group_fd = fd_group[fd]
        if group_fd in fd_group:
            del fd_group[group_fd]
        fd_group.pop(fd, None)

        if group_fd in fd_to_socket:
            try:
                epoll.unregister(group_fd)
            except Exception:
                pass
            fd_to_socket[group_fd].close()
            del fd_to_socket[group_fd]
            fd_to_buffer.pop(group_fd, None)
            fd_role.pop(group_fd, None)
            remote_last_time.pop(group_fd, None)
            if group_fd in segment_requests:
                del segment_requests[group_fd]

    try:
        epoll.unregister(fd)
    except Exception:
        pass

    if fd in fd_to_socket:
        fd_to_socket[fd].close()
        del fd_to_socket[fd]
        fd_to_buffer.pop(fd, None)
        fd_role.pop(fd, None)
        remote_last_time.pop(fd, None)
        if fd in segment_requests:
            del segment_requests[fd]

if __name__ == "__main__":
    main()
