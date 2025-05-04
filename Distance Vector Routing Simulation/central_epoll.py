import socket
import select
import json
import time

class Node:
    def __init__(self, name: str, port: int, ep: select.epoll):
        self.name       = name
        self.port       = port
        self.epoll      = ep

        # neighbors: name -> port
        self.neighbors  = {}
        # node_cost: best known cost to each destination
        self.node_cost  = {}
        # node_port: port of the next hop for each destination
        self.node_port  = {}

        # bind a nonblocking UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', port))
        self.sock.setblocking(False)

        # register for read events
        self.epoll.register(self.sock.fileno(), select.EPOLLIN)

    def add_neighbor(self, neighbor_name: str, neighbor_port: int, cost: int):
        """Called at setup time to install a direct link."""
        self.neighbors[neighbor_name] = neighbor_port
        self.node_cost[neighbor_name] = cost
        # next hop to reach neighbor_name is directly that neighbor
        self.node_port[neighbor_name] = neighbor_port

    def add_route(self, sender: str, dest: str, next_hop_port: int, advertised_cost: int):
        """
        Called whenever we receive an advertisement from `sender`.
        advertised_cost is the cost sender claimed to reach `dest` from itself.
        """
        # total cost = cost to reach sender + advertised cost
        if sender not in self.node_cost:
            # we have no route to sender yet
            return
        total = self.node_cost[sender] + advertised_cost

        # ignore routes to ourselves
        if dest == self.name:
            return

        # if we already have a better or equal route, ignore
        if dest in self.node_cost and self.node_cost[dest] <= total:
            return

        # otherwise adopt this route
        self.node_cost[dest] = total
        self.node_port[dest] = next_hop_port

        # and re-advertise this improved route to all our neighbors
        self._broadcast(dest, total)

    def _broadcast(self, dest: str, cost: int):
        """
        Send a JSON advertisement to each neighbor:
          { "sender": self.name,
            "dest":   dest,
            "port":   self.port,
            "cost":   cost }
        """
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
        Kick off the first wave of advertisements:
        tell each neighbor about every other direct link we have.
        """
        for nbr_name, nbr_port in self.neighbors.items():
            for other, c in self.node_cost.items():
                if other == nbr_name:
                    continue
                # “I can reach `other` at cost=c, and your next-hop port is nbr_port”
                msg = json.dumps({
                    "sender": self.name,
                    "dest":   other,
                    "port":   self.port,
                    "cost":   c
                }).encode()
                self.sock.sendto(msg, ('127.0.0.1', nbr_port))

    def handle_receive(self):
        """
        Read one datagram (if any), parse, then call add_route().
        """
        try:
            data, addr = self.sock.recvfrom(4096)
        except BlockingIOError:
            return
        m = json.loads(data.decode())
        self.add_route(
            sender       = m["sender"],
            dest         = m["dest"],
            next_hop_port= m["port"],
            advertised_cost = m["cost"]
        )

    def print_routes(self):
        print(f"{self.name} routing table:")
        for dest, cost in self.node_cost.items():
            nh = self.node_port[dest]
            print(f"  -> {dest:>2}  cost={cost:>2} via port {nh}")
        print()


if __name__ == "__main__":
    # 1) build epoll instance
    ep = select.epoll()

    # 2) instantiate nodes U,V,W,X,Y,Z on ports 9100..9105
    base_port = 9100
    names     = ["U","V","W","X","Y","Z"]
    nodes     = {}
    for nm in names:
        node = Node(nm, base_port, ep)
        nodes[nm] = node
        base_port += 1

    # 3) wire up the topology with initial direct costs
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

    # 4) kick off one calibration round
    for node in nodes.values():
        node.calibrate()

    # 5) drive the epoll loop until it quiets out
    #    (timeout if no new events for 2 seconds)
    last_activity = time.time()
    while True:
        events = ep.poll(0.5)
        if not events:
            if time.time() - last_activity > 2:
                break
            else:
                continue

        last_activity = time.time()
        for fileno, evt in events:
            # dispatch to whichever node owns that fileno
            for node in nodes.values():
                if node.sock.fileno() == fileno:
                    node.handle_receive()

    # 6) print final tables
    for node in nodes.values():
        node.print_routes()
