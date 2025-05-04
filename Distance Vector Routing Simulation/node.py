class Node:

    def __init__(self, name, port):
        self.name = name
        self.port = port
        self.neighbors = []
        self.node_port = {}
        self.node_cost = {}
        # self.main()

    def add_neighbor(self, name, port, cost):
        self.neighbors.append(name)
        self.node_port[name] = port
        self.node_cost[name] = cost
    
    def add_route(self, sender, name, port, cost):
        cost += self.node_cost[sender]
        # If advertised route to self
        if name is self.name:
            return
        # If new route costs more than or equal to an existing route, discard
        if name in self.node_cost:
            if self.node_cost[name] <= cost:
                return

        self.node_port[name] = port
        self.node_cost[name] = cost
        self.advertise(name, port, cost)

    def advertise(self, name, port, cost):
        for neighbor in self.neighbors:
            self.node_port[neighbor].add_route(self.name, name, port, cost)

    def calibrate(self):
        for neighbor in self.neighbors:
            for other in self.neighbors:
                if neighbor is not other:
                    # Advertise to each neighbor the routes of the other neighbors
                    print(self.node_port[neighbor])
                    print("^^^")
                    self.node_port[neighbor].add_route(self.name, other, self.node_port[other], self.node_cost[other])

    def print(self):
        print(self.name, ": ", end='')
        for node, cost in self.node_cost.items():
            print(node, " ", cost, " | ", end='')
        print()
        
def write_dist(node1, node2, cost):
    node1.add_neighbor(node2.name, node2.port, cost)
    node2.add_neighbor(node1.name, node1.port, cost)



U = Node("U", -1)
V = Node("V", -1)
W = Node("W", -1)
X = Node("X", -1)
Y = Node("Y", -1)
Z = Node("Z", -1)

list = {U, V, W, X, Y, Z}

for node in list:
    node.port = node

write_dist(U, V, 7)
write_dist(U, W, 3)
write_dist(U, X, 5)

write_dist(W, X, 4)
write_dist(W, Y, 8)
write_dist(W, V, 3)

write_dist(Y, V, 4)
write_dist(Y, X, 7)
write_dist(Y, Z, 2)

write_dist(Z, X, 9)

for node in list:
    node.calibrate()

for node in list:
    node.print()