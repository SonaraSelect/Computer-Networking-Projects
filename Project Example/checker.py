from socket import *
import sys
import random
import os
import time

if len(sys.argv) < 7:
    sys.stderr.write('Usage: %s <ip> <port> <#trials>\
            <#writes and reads per trial>\
            <max # bytes to write at a time> <#connections> \n' % (sys.argv[0]))
    sys.exit(1)

serverHost = gethostbyname(sys.argv[1])
serverPort = int(sys.argv[2])
numTrials = int(sys.argv[3])
numWritesReads = int(sys.argv[4])
numBytes = int(sys.argv[5])
numConnections = int(sys.argv[6])

socketList = []

RECV_TOTAL_TIMEOUT = 0.1
RECV_EACH_TIMEOUT = 0.01


for i in range(numConnections):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((serverHost, serverPort))
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    socketList.append(s)


for i in range(numTrials):
    socketSubset = []
    randomData = []
    randomLen = []
    socketSubset = random.sample(socketList, numConnections)
    for j in range(numWritesReads):
        random_len = random.randrange(1, numBytes)
        random_string = os.urandom(random_len)
        randomLen.append(random_len)
        randomData.append(random_string)
        socketSubset[j].send(random_string)

    for j in range(numWritesReads):
        data = socketSubset[j].recv(randomLen[j])
        start_time = time.time()
        while True:
            if len(data) == randomLen[j]:
                break
            socketSubset[j].settimeout(RECV_EACH_TIMEOUT)
            data += socketSubset[j].recv(randomLen[j])
            if time.time() - start_time > RECV_TOTAL_TIMEOUT:
                break
        if data != randomData[j]:
            sys.stderr.write("Error: Data received is not the same as sent! \n")
            sys.exit(1)

for i in range(numConnections):
    socketList[i].close()

print("Success!")

