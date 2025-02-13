import socket
import json
import select
import uuid

# Load backend server configuration
def load_backend_servers(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config['backend_servers']

# Create a non-blocking socket
def create_server_socket(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)
    server.bind((host, port))
    server.listen(100)
    return server

class HTTPProxy:
    def __init__(self, host, port, backend_servers):
        self.server_socket = create_server_socket(host, port)
        self.epoll = select.epoll()
        self.epoll.register(self.server_socket.fileno(), select.EPOLLIN)
        self.connections = {}
        self.requests = {}
        self.responses = {}
        self.backend_servers = backend_servers
        self.server_index = 0
    
    def get_next_backend(self):
        """Round-robin selection of backend servers."""
        backend = self.backend_servers[self.server_index]
        self.server_index = (self.server_index + 1) % len(self.backend_servers)
        return backend
    
    def handle_client_request(self, client_socket):
        data = client_socket.recv(4096)
        if not data:
            return None
        backend = self.get_next_backend()
        backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_socket.setblocking(False)
        backend_socket.connect_ex((backend['ip'], backend['port']))
        request_id = str(uuid.uuid4())
        modified_data = data.replace(b'HTTP/1.1', b'HTTP/1.1\r\nX-Request-ID: ' + request_id.encode())
        self.epoll.register(backend_socket.fileno(), select.EPOLLOUT)
        self.connections[backend_socket.fileno()] = backend_socket
        self.requests[backend_socket.fileno()] = modified_data
        self.responses[backend_socket.fileno()] = client_socket
    
    def run(self):
        try:
            while True:
                events = self.epoll.poll(1)
                for fileno, event in events:
                    if fileno == self.server_socket.fileno():
                        client_socket, addr = self.server_socket.accept()
                        client_socket.setblocking(False)
                        self.epoll.register(client_socket.fileno(), select.EPOLLIN)
                        self.connections[client_socket.fileno()] = client_socket
                    elif event & select.EPOLLIN:
                        self.handle_client_request(self.connections[fileno])
                    elif event & select.EPOLLOUT:
                        backend_socket = self.connections[fileno]
                        backend_socket.sendall(self.requests[fileno])
                        self.epoll.modify(fileno, select.EPOLLIN)
                    elif event & select.EPOLLHUP:
                        self.epoll.unregister(fileno)
                        self.connections[fileno].close()
                        del self.connections[fileno]
        finally:
            self.epoll.unregister(self.server_socket.fileno())
            self.epoll.close()
            self.server_socket.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python proxy.py <server_config.json>")
        sys.exit(1)
    backend_servers = load_backend_servers(sys.argv[1])
    proxy = HTTPProxy("0.0.0.0", 9000, backend_servers)
    proxy.run()
