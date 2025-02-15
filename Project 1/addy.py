import argparse
import json
import socket
import select
import errno

# Constants
MAX_CONNECTION_REQUESTS = 5  # Max number of file descriptors


class LoadBalancer:
    def __init__(self, servers):
        self.servers = servers
        self.index = 0

    def get_next_server(self):
        server = self.servers[self.index]
        self.index = (self.index + 1) % len(self.servers)
        return server


class MySocket:
    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setblocking(False)  # Set non-blocking mode
        else:
            self.sock = sock

    def connect(self, host, port):
        self.sock.connect_ex((host, port))  # Non-blocking connect

    def send(self, msg):
        """Send the entire message in non-blocking mode."""
        total_sent = 0
        while total_sent < len(msg):
            sent = self.sock.send(msg[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent

    def receive(self, max_bytes=4096):
        return MySocket.receive(self.sock, max_bytes)

    @staticmethod
    def receive(s, max_bytes=4096):
        """Receive the entire message in non-blocking mode."""
        chunks = []
        bytes_received = 0

        while bytes_received < max_bytes:
            chunk = s.recv(min(max_bytes - bytes_received, 2048))  # Max size for each read is 2048 bytes
            if not chunk:
                # Connection closed or error
                raise RuntimeError("Socket connection broken")
            chunks.append(chunk)
            bytes_received += len(chunk)

        return b''.join(chunks)


def load_servers_config(config_path):
    with open(config_path, 'r') as f:
        config = json.load(f)
    return config["backend_servers"]


def create_server_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(MAX_CONNECTION_REQUESTS)
    return s


def handle_new_client(client_socket):
    """Handle a new client connection by accepting it."""
    client_socket.setblocking(False)
    epoll.register(client_socket.fileno(), select.EPOLLIN)


def handle_client_request(client_socket, load_balancer):
    """Forward client request to a backend server and register backend socket."""
    try:
        request_data = MySocket.receive(client_socket)

        if request_data:
            backend_server = load_balancer.get_next_server()
            backend_socket = MySocket()  # Create a new backend socket instance

            # Connect to the backend server (non-blocking)
            backend_socket.connect(backend_server["ip"], backend_server["port"])

            # Send the request data to the backend (non-blocking)
            backend_socket.send(request_data)

            # Register the backend socket with epoll to monitor for incoming data
            epoll.register(backend_socket.sock.fileno(), select.EPOLLIN)

            # Map the backend socket to the client socket for later response handling
            request_map[backend_socket.sock.fileno()] = client_socket
        else:
            # Client closed the connection, unregister and close it
            epoll.unregister(client_socket.fileno())
            client_socket.close()
    except Exception as e:
        # Handle any exceptions (like connection failures or broken sockets)
        print(f"Error while handling client request: {e}")
        epoll.unregister(client_socket.fileno())
        client_socket.close()


def handle_backend_response(backend_socket):
    """Forward backend response to the appropriate client."""
    try:
        response_data = MySocket.receive(backend_socket)

        if response_data:
            # Get the corresponding client socket from the request_map
            client_socket = request_map.pop(backend_socket.fileno(), None)
            if client_socket:
                # Send response data to the client
                client_socket.sendall(response_data)
                # Keep the connection open for HTTP 1.1 pipelining (if 'Connection: keep-alive' header exists)
                if b"Connection: keep-alive" in response_data:
                    epoll.register(client_socket.fileno(), select.EPOLLIN)
                else:
                    # If 'Connection: close' is received, close the connection
                    epoll.unregister(client_socket.fileno())
                    client_socket.close()

                # Unregister and clean up backend socket
                epoll.unregister(backend_socket.fileno())
                backend_socket.close()
            else:
                # Handle case where backend response has no mapped client (shouldn't happen if request_map is correct)
                print(f"No client socket found for backend socket {backend_socket.fileno()}")
        else:
            print(f"No data received from backend socket {backend_socket.fileno()}")
    except Exception as e:
        print(f"Error handling backend response: {e}")
        epoll.unregister(backend_socket.fileno())
        backend_socket.close()


def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="HTTP Proxy and Load Balancer")
    parser.add_argument('config', type=str, help="Path to the backend server configuration file")
    args = parser.parse_args()

    # Load backend servers from configuration file
    backend_servers = load_servers_config(args.config)
    load_balancer = LoadBalancer(backend_servers)

    # Create and bind the proxy server socket
    proxy_socket = create_server_socket("0.0.0.0", 9000)

    # Set up epoll for event-driven I/O
    global epoll, request_map
    epoll = select.epoll()
    request_map = {}  # Maps backend sockets to client sockets

    # Register the proxy server socket with epoll
    epoll.register(proxy_socket.fileno(), select.EPOLLIN)

    # Event loop
    try:
        while True:
            events = epoll.poll()  # Wait for events on monitored FDs
            for fd, event in events:
                if fd == proxy_socket.fileno():
                    # Accept new client connection
                    client_socket, _ = proxy_socket.accept()
                    handle_new_client(client_socket)
                elif event & select.EPOLLIN:
                    if fd in request_map:  # Backend socket
                        handle_backend_response(fd)
                    else:  # Client socket
                        handle_client_request(fd, load_balancer)
                elif event & select.EPOLLERR or event & select.EPOLLHUP:
                    # Handle error or hung up events
                    print(f"Socket {fd} has an error or was closed.")
                    epoll.unregister(fd)
                    fd.close()

    except KeyboardInterrupt:
        print("Shutting down proxy...")
    finally:
        # Close epoll and all sockets
        epoll.unregister(proxy_socket.fileno())
        proxy_socket.close()
        for client_socket in request_map.values():
            client_socket.close()


if __name__ == "__main__":
    main()
