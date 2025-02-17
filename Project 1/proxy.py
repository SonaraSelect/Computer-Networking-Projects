#!/usr/bin/env python3

import resource
import socket
import select
import json
import sys
import os
import re

class Proxy:
    """
    A more advanced HTTP proxy skeleton with partial buffering/parsing
    to handle multiple/pipelined requests more cleanly.
    """

    REQUEST_REGEX = re.compile(
        br'^(.*?)\r\n\r\n',
        re.DOTALL
    )

    def __init__(self, host, port, backend_config_path):
        self.host = host
        self.port = port
        self.servers = self._load_servers(backend_config_path)
        self.server_cnt = len(self.servers)
        self.current_server_index = 0

        # Set up epoll and temp socket collection dict
        self.epoll = select.epoll()
        self.fd_to_socket = {}

        # Set up dicts for temp sockets
        self.client_to_server = {}
        self.server_to_client = {}

        # Set up buffer dicts
        self.client_buffers = {}
        self.server_buffers = {}

        # Make listening socket
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind((self.host, self.port))
        self.listen_sock.listen()
        self.listen_sock.setblocking(False)

        self.fd_to_socket[self.listen_sock.fileno()] = self.listen_sock
        self.epoll.register(self.listen_sock.fileno(), select.EPOLLIN)

        print(f"Proxy listening on {self.host}:{self.port}")
        print(f"Loaded back-end servers: {self.servers}")

    def _load_servers(self, path):
        with open(path, 'r') as f:
            data = json.load(f)
        return data.get("backend_servers", [])

    def _get_next_server(self):
        """Select next server via round robin scheduling"""
        server = self.servers[self.current_server_index]
        self.current_server_index = (self.current_server_index + 1) % self.server_cnt
        return server

    def _connect_to_server(self):
        """Make non-blocking socket to backend server"""
        server_info = self._get_next_server()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect((server_info["ip"], server_info["port"]))
        except BlockingIOError:
            pass
        return s

    def _accept_new_connection(self):
        """Accept a new connection"""
        # Check listening socket still valid
        if self.listen_sock.fileno() < 0:
            return

        try:
            client_sock, client_addr = self.listen_sock.accept()
        except OSError as e:
            return

        client_sock.setblocking(False)
        cfd = client_sock.fileno()
        self.fd_to_socket[cfd] = client_sock
        self.epoll.register(cfd, select.EPOLLIN)
        self.client_buffers[cfd] = b''


    def _close_connection(self, fd):
        """Close client and server connections"""
        if fd in self.fd_to_socket:
            socket = self.fd_to_socket[fd]
            self.epoll.unregister(fd)
            socket.close()
            del self.fd_to_socket[fd]

        # Remove buffers
        self.client_buffers.pop(fd, None)
        self.server_buffers.pop(fd, None)

    def _parse_http_requests(self, buffer):
        """Parse one or more http requests from buffer"""
        requests = []
        while True:
            # Look for delimiter
            match = self.REQUEST_REGEX.search(buffer)
            if not match:
                break  # Wait for more data

            end = match.end()
            headers = buffer[:end]

            # Convert headers to string
            try:
                headers_str = headers.decode("utf-8", errors="replace")
            except Exception:
                headers_str = ""

            # Split at content length header
            content_length = 0
            for line in headers_str.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        content_length = 0
                    break

            # Total request length
            full_length = end + content_length

            # Check if full request
            if len(buffer) < full_length:
                break  # The body hasn't been fully received yet

            # Extract complete request
            request = buffer[:full_length]
            requests.append(request)

            # Remove processed request from buffer
            buffer = buffer[full_length:]

        return requests, buffer

    def _handle_client_readable(self, fd):
        """
        Read 4096 B of data from client, if applicable
        and forward data to server when all data collected
        """
        client_sock = self.fd_to_socket[fd]
        try:
            chunk = client_sock.recv(4096)
            if not chunk:
                # Close if client socket has no more data to send
                self._close_connection(fd)
                return
            self.client_buffers[fd] += chunk

        except ConnectionResetError:
            # If client has connection error during reading
            self._close_connection(fd)
            return

        # Parse one or more requests from the buffer
        requests, leftover = self._parse_http_requests(self.client_buffers[fd])
        self.client_buffers[fd] = leftover  # store leftover unparsed data

        # Forward completed requests to backend server
        for req in requests:
            self._forward_new_request(fd, req)

    def _forward_new_request(self, client_fd, request_bytes):
        """Forward client request to server"""
        # Connect client to server if need be
        if client_fd not in self.client_to_server:
            server_socket = self._connect_to_server()
            server_fd = server_socket.fileno()

            self.fd_to_socket[server_fd] = server_socket
            self.epoll.register(server_fd, select.EPOLLIN)

            self.client_to_server[client_fd] = server_fd
            self.server_to_client[server_fd] = client_fd

            # Create partial response buffer if needed
            self.server_buffers[server_fd] = b''
        else:
            # Reuse previous server socket
            server_fd = self.client_to_server[client_fd]

        # Forward request to the server
        server_socket = self.fd_to_socket[server_fd]
        try:
            server_socket.sendall(request_bytes)
        except BrokenPipeError:
            self._close_connection(server_fd)

    def _handle_server_readable(self, server_fd):
        """Read data into server buffer if server fd readable"""
        
        server_sock = self.fd_to_socket[server_fd]
        client_fd = self.server_to_client[server_fd]

        try:
            chunk = server_sock.recv(4096)
            if not chunk:
                # Server is closed.
                self._close_connection(server_fd)
                return
            # Write chunk to client
            self.fd_to_socket[client_fd].sendall(chunk)
        except ConnectionResetError:
            self._close_connection(server_fd)

    def run(self):
        try:
            while True:
                events = self.epoll.poll(timeout=1)
                for fd, event in events:
                    # Accept new connection to listening socket
                    if fd == self.listen_sock.fileno():
                        self._accept_new_connection()
                        continue

                    # Close socket due to client hang up or error
                    if event & (select.EPOLLHUP | select.EPOLLERR):
                        self._close_connection(fd)
                        continue

                    # If data is available to read
                    if event & select.EPOLLIN:
                        if fd in self.client_to_server:
                            # Data from client socket
                            self._handle_client_readable(fd)
                        elif fd in self.server_to_client:
                            # Data from server socket
                            self._handle_server_readable(fd)
                        else:
                            # Data possibly from client without a server (yet)
                            self._handle_client_readable(fd)

                    # For advanced usage, handle EPOLLOUT for partial writes or async connect

        except KeyboardInterrupt:
            print("Proxy shutting down (KeyboardInterrupt).")
        finally:
            # Cleanup
            self.epoll.unregister(self.listen_sock.fileno())
            self.epoll.close()
            self.listen_sock.close()
            print("Proxy closed.")


def main():
    # Increase file descriptor limits to handle all connections
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65535), hard))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)


    # Set up proxy information and backend path
    host = "127.0.0.1"
    port = 9000
    backend_config_path = "servers.conf"

    proxy = Proxy(host, port, backend_config_path)
    proxy.run()


if __name__ == "__main__":
    main()
