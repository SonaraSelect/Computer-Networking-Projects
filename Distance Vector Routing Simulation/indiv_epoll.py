import socket
import select
import json
import threading
import time

class Node:
    def __init__(self, name: str, port: int):
        self.name       = name
        self.port       = port
        self.neighbors  = {}      # name -> port
        self.node_cost  = {}      # dest name -> best cost
        self.node_port  = {}      # dest name -> next-hop port

        # --- set up nonblocking UDP socket + its own epoll ---
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', port))
        self.sock.setblocking(False)

        self.epoll = select.epoll()
        self.epoll.register(self.sock.fileno(), select.EPOLLIN)

        # threading control
        self.running = False
        self.thread  = threading.Thread(target=self._run_loop, daemon=True)

    def start(self):
        self.running = True
        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join()
        self.epoll.unregister(self.sock.fileno())
        self.sock.close()

    def add_neighbor(self, nbr_name: str, nbr_port: int, cost: int):
        """Called once at setup to install a direct link."""
        self.neighbors[nbr_name] = nbr_port
        self.node_cost[nbr_name] = cost
        self.node_port[nbr_name] = nbr_port

    def add_route(self, sender: str, dest: str, next_hop_port: int, advertised_cost: int):
        """Process an incoming advertisement."""
        # we must already know how to reach sender
        if sender not in self.node_cost:
            return

        # total cost = cost to sender + sender’s advertised_cost
        total = self.node_cost[sender] + advertised_cost

        # ignore routes to ourselves
        if dest == self.name:
            return

        # if we have a better-or-equal route, skip
        if dest in self.node_cost and self.node_cost[dest] <= total:
            return

        # adopt the new cheaper route
        self.node_cost[dest] = total
        self.node_port[dest] = next_hop_port

        # re-broadcast this improved route
        self._broadcast(dest, total)

    def _broadcast(self, dest: str, cost: int):
        """Send a JSON advertisement to all direct neighbors."""
        msg = json.dumps({
            "sender": self.name,
            "dest":   dest,
            "port":   self.port,
            "cost":   cost
        }).encode()
        for nbr_port in self.neighbors.values():
            self.sock.sendto(msg, ('127.0.0.1', nbr_port))

    def calibrate(self):
        """
        Kick-off one round: tell each neighbor about every
        other direct route you know.
        """
        for nbr_name, nbr_port in self.neighbors.items():
            for other, c in self.node_cost.items():
                if other == nbr_name:
                    continue
                msg = json.dumps({
                    "sender": self.name,
                    "dest":   other,
                    "port":   self.port,
                    "cost":   c
                }).encode()
                self.sock.sendto(msg, ('127.0.0.1', nbr_port))

    def _run_loop(self):
        """Thread target: poll on our own epoll and handle incoming."""
        while self.running:
            events = self.epoll.poll(1.0)
            for fileno, event in events:
                if fileno == self.sock.fileno():
                    self._handle_receive()

    def _handle_receive(self):
        try:
            data, _ = self.sock.recvfrom(4096)
        except BlockingIOError:
            return
        m = json.loads(data.decode())
        self.add_route(
            sender        = m["sender"],
            dest          = m["dest"],
            next_hop_port = m["port"],
            advertised_cost = m["cost"]
        )

    def print_routes(self):
        print(f"{self.name} routing table:")
        for dest, cost in self.node_cost.items():
            nh = self.node_port[dest]
            print(f"  -> {dest:>2}  cost={cost:>2} via port {nh}")
        print()


if __name__ == "__main__":
    # 1) create & start nodes U–Z on ports 9100–9105
    base_port = 9100
    names     = ["U","V","W","X","Y","Z"]
    nodes     = {}
    for nm in names:
        node = Node(nm, base_port)
        nodes[nm] = node
        node.start()
        base_port += 1

    # 2) wire up the graph’s direct edges
    edges = [
        ("U","V",7), ("U","W",3), ("U","X",5),
        ("W","X",4), ("W","Y",8), ("W","V",3),
        ("Y","V",4), ("Y","X",7), ("Y","Z",2),
        ("Z","X",9)
    ]
    for a, b, cost in edges:
        na, nb = nodes[a], nodes[b]
        na.add_neighbor(b, nb.port, cost)
        nb.add_neighbor(a, na.port, cost)

    # 3) kick off the first wave
    for node in nodes.values():
        node.calibrate()

    # 4) let the distributed epoll loops run for a bit
    time.sleep(2.0)

    # 5) tear down and print results
    for node in nodes.values():
        node.stop()
    for node in nodes.values():
        node.print_routes()
