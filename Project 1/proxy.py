#!/usr/bin/env python3

import socket
import select
import json
import sys
import os

class Proxy:
    """
    A simplified HTTP proxy with load-balancing using epoll. 
    This is a *skeleton* to illustrate the major steps and data flows.
    """

    #--> set up listening socket, load list of backend servers from json, initialize epoll
    def __init__(self, host, port, backend_config_path):
        """
        Initialize proxy:
          - host, port: where the proxy itself will listen
          - backend_config_path: path to the JSON file containing back-end servers
        """
        self.host = host
        self.port = port

        # Load back-end servers from JSON config
        self.servers = self._load_servers(backend_config_path)
        self.num_servers = len(self.servers)
        self.current_server_index = 0

        # Create a dictionary to map file descriptors (FDs) to actual sockets
        self.fd_to_socket = {}

        # Track the pairing of client FD -> server FD and server FD -> client FD
        self.client_to_server = {}
        self.server_to_client = {}

        # Create the epoll object
        self.epoll = select.epoll()

        # Create the listening socket for incoming client connections
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind((self.host, self.port))
        self.listen_sock.listen()
        self.listen_sock.setblocking(False)

        # Register the listening socket with epoll for "readable" events
        self.epoll.register(self.listen_sock.fileno(), select.EPOLLIN)

        print(f"Proxy listening on {self.host}:{self.port}")
        print(f"Loaded back-end servers: {self.servers}")

    def _load_servers(self, path):
        """
        Load the JSON file containing the list of back-end servers.
        Expected format:
            {
                "backend_servers": [
                    {"ip": "127.0.0.1", "port": 8001},
                    {"ip": "127.0.0.1", "port": 8002},
                    ...
                ]
            }
        """
        with open(path, 'r') as f:
            data = json.load(f)
        return data.get("backend_servers", [])

    def _get_next_server(self):
        """
        Simple round-robin: pick the next back-end server in the list.
        """
        server = self.servers[self.current_server_index]
        self.current_server_index = (self.current_server_index + 1) % self.num_servers
        return server

    def _connect_to_server(self):
        """
        Creates and returns a non-blocking socket connected to the next back-end server.
        """
        server_info = self._get_next_server()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)

        # Initiate the connection
        try:
            s.connect((server_info["ip"], server_info["port"]))
        except BlockingIOError:
            # This is expected because we're in non-blocking mode,
            # so the connect may not complete immediately.
            pass

        return s

    def _accept_new_connection(self):
        """
        Accept a new client, set non-blocking, register it with epoll.
        """
        client_sock, client_addr = self.listen_sock.accept()
        client_sock.setblocking(False)
        self.fd_to_socket[client_sock.fileno()] = client_sock
        self.epoll.register(client_sock.fileno(), select.EPOLLIN)
        print(f"Accepted new connection from {client_addr}")

    def _close_connection(self, fd):
        """
        Gracefully close a connection (client or server), and clean up all mappings.
        """
        if fd in self.fd_to_socket:
            sock = self.fd_to_socket[fd]
            # Unregister the FD from epoll and close the socket
            self.epoll.unregister(fd)
            sock.close()
            del self.fd_to_socket[fd]

        # If this FD was a client, close the associated server
        if fd in self.client_to_server:
            server_fd = self.client_to_server[fd]
            if server_fd in self.fd_to_socket:
                self._close_connection(server_fd)
            del self.client_to_server[fd]

        # If this FD was a server, close the associated client
        if fd in self.server_to_client:
            client_fd = self.server_to_client[fd]
            if client_fd in self.fd_to_socket:
                self._close_connection(client_fd)
            del self.server_to_client[fd]

    def _forward_data(self, src_fd, dest_fd):
        """
        Forward available data from src_fd to dest_fd.
        If the destination is not ready or an error occurs, close the connections.
        """
        try:
            data = self.fd_to_socket[src_fd].recv(4096)
            if data:
                self.fd_to_socket[dest_fd].sendall(data)
            else:
                # No data means the remote side closed the connection
                self._close_connection(src_fd)
        except ConnectionResetError:
            # Source closed forcibly
            self._close_connection(src_fd)
        except socket.error:
            # Some other socket error
            self._close_connection(src_fd)

    def run(self):
        """
        Main loop using epoll to handle:
          - new incoming connections
          - data from clients
          - data from servers
        """
        try:
            while True:
                events = self.epoll.poll(timeout=1)  # 1 second timeout, or None for blocking
                for fd, event in events:
                    # If the event is on our main listening socket, accept a new client
                    if fd == self.listen_sock.fileno():
                        self._accept_new_connection()
                        continue

                    # Check if there's an error event on this FD
                    if event & (select.EPOLLHUP | select.EPOLLERR):
                        self._close_connection(fd)
                        continue

                    # If we have data to read
                    if event & select.EPOLLIN:
                        # If this FD is a client
                        if fd in self.client_to_server:
                            server_fd = self.client_to_server[fd]
                            # We forward data from client to its associated server
                            self._forward_data(fd, server_fd)
                        # If this FD is a server
                        elif fd in self.server_to_client:
                            client_fd = self.server_to_client[fd]
                            # Forward data from server to client
                            self._forward_data(fd, client_fd)
                        else:
                            # This FD has no server associated yet -> new request from client
                            server_sock = self._connect_to_server()
                            server_fd = server_sock.fileno()

                            # Register server sock with epoll for readability
                            self.fd_to_socket[server_fd] = server_sock
                            self.epoll.register(server_fd, select.EPOLLIN)

                            # Map them in both directions
                            self.client_to_server[fd] = server_fd
                            self.server_to_client[server_fd] = fd

                            # Forward the initial data from client to server
                            self._forward_data(fd, server_fd)

                    # If we can write on this FD (EPOLLOUT), in some designs we would
                    # handle partial writes or connect() completions here.
                    # For simplicity, we skip that in this skeleton.
                    if event & select.EPOLLOUT:
                        pass

        except KeyboardInterrupt:
            print("Proxy shutting down due to KeyboardInterrupt.")
        finally:
            # Clean up
            self.epoll.unregister(self.listen_sock.fileno())
            self.epoll.close()
            self.listen_sock.close()
            print("Proxy closed.")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port> <backend_config.json>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    backend_config_path = sys.argv[3]

    if not os.path.exists(backend_config_path):
        print(f"Error: config file {backend_config_path} does not exist.")
        sys.exit(1)

    proxy = Proxy(host, port, backend_config_path)
    proxy.run()

if __name__ == "__main__":
    main()
