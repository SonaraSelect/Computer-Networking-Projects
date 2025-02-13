
import socket
import select
import json
import sys
import errno


# init (initialization)
# check servers for next available
# checking specific backend server for availability
# creating a new connection
# closing a connection
# Taking a request from a client to backend server
# Sending response from backend server to client
# Send information to client from server if fully connected
# run function that calls them when needed


# Create a socket to start receiving requests
# Host will be 127.0.0.1 and port 8001-8003 I think
def init_server_socket(host, port):
    # Make a socket supporting up to 10 concurrent connections
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(host, port)
    server.listen(100)
    return server

# Edge trigger epoll
# def main()


# -------------------------


# Step 1: Load Backend Servers from servers.conf
with open(sys.argv[1], 'r') as config_file:
    config = json.load(config_file)
    backend_servers = [(srv['ip'], srv['port']) for srv in config['backend_servers']]

backend_index = 0

# Step 2: Create a Listening Socket (Proxy Socket)
def create_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind((host, port))
    s.listen(100)  # Backlog of 100 connections
    return s

proxy_host = '127.0.0.1'
proxy_port = 9000
listen_sock = create_socket(proxy_host, proxy_port)

# Step 3: Create epoll object and register the listening socket
epoll = select.epoll()
epoll.register(listen_sock.fileno(), select.EPOLLIN)

# Step 4: Data Structures for Managing Connections
fd_to_socket = {listen_sock.fileno(): listen_sock}
connections = {}

# Step 5: Event Loop
try:
    while True:
        events = epoll.poll(timeout=1)
        for fd, event_mask in events:
            sock = fd_to_socket[fd]

            if sock is listen_sock:
                client_sock, client_addr = listen_sock.accept()
                client_sock.setblocking(False)
                epoll.register(client_sock.fileno(), select.EPOLLIN)
                fd_to_socket[client_sock.fileno()] = client_sock
                connections[client_sock] = {'type': 'client', 'in_buf': b'', 'out_buf': b''}
                print(f"New client connected from {client_addr}")
            
            elif event_mask & select.EPOLLIN:
                try:
                    data = sock.recv(4096)
                    if data:
                        connections[sock]['in_buf'] += data
                        print(f"Received data from client: {data[:50]}...")
                    else:
                        epoll.unregister(fd)
                        sock.close()
                        del fd_to_socket[fd]
                        del connections[sock]
                        print("Client disconnected")
                except socket.error as e:
                    if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        print(f"Socket error: {e}")
                        epoll.unregister(fd)
                        sock.close()
                        del fd_to_socket[fd]
                        del connections[sock]

except KeyboardInterrupt:
    print("Shutting down...")
finally:
    epoll.close()
    listen_sock.close()
