# Welcome to my Simplified TCP Implementation!
*by Audrey Michel*

# CHECKPOINT 2

First I must mention one specific bug: right now the handshake ACKs, SYNs, and SYN+ACKs are not always retransmitted, so there is a small chance of a packet loss occuring at the beginning, leaving the server or clients stuck in the handshake states.

Otherwise, everything else is fully implemented. The tcp congestion control states and dynamic change of the send window size are implemented, and every time a value is changed it will be printed out to console.

## congestion window

One eccentricity in my design is that the sending sliding window works by first dividing the text into packets and buffering them in a to-send list called frames. This means that when a frame is to be sent, the packet is simply read from the frames list and sent. The buffering of packets also works in the same way.

This presents one issue, where the window sizes and congestion window are now in unit of frames, rather than bytes. My solution to this was to multiply all values by MSS to convert them back to bytes for ease of debugging.

## congestion control fsm

Everything else is implemented as expected.

## PYTHON 3 IS NEEDED TO RUN MY CODE !!
Run on Ubuntu 24.04.1 LTS on WSL2
Kernel: 5.15.167.4-microsoft-standard-WSL2
(alternate kernel needed to simulate network congestion)




# LEGACY README FROM CHECKPOINT 1

Now, for checkpoint one I was only able to implement the FSM and estimated RTT. There are still some remaining bugs. For example, sometimes the server side will remain stuck in a loop and never close. I have been unable to reliably recreate this bug, as it randomly goes away as fast as it came, even without having made any changes.

**One important note is that the server side will take a moment before it can fully close.** While the client closes nearly instantly, the server will take much longer. This kink is still being worked out.

Another issue is that I was unable to stop the client from closing before the server is done sending data. I suspected this issue to be an issue with client.py, and I have accordingly added a time.sleep(10) before the client closes, but this **has not fixed this issue of only alice.txt being successfully sent.**

While I am fixing this bug, I have made it so segments can only be sent while in the ESTABLISHED state.

Now, onto how I implemented the FSM.

# FSM

The states are stored in an enum assigned to transport.py. The transitions between them are handled primarily in the backend, where you will see a big match/case statement that handles the received packets.

We begin in LISTEN. When send() is called, send_syn_packet() is called within it and a SYN packet is sent and after a SYN+ACK is received an ACK will be sent before transitioning to ESTABLISHED. Here in established is where all the data transfer will take place. My goal is to stay in ESTABLISHED until the final randomized data from server is received by the client.

After the data is finished transmitting, send_fin_packet() and the transition to FIN_SENT will not begin until it is called in close(). As you can see, my issue is with the client calling close() too early, despite the sleep statement.

Other than that, the backend handles most of the state transitions, following the FSM very tightly. It should be self explanatory. **The CLOSE_WAIT and TIME_WAIT timer is 2x the smoothed RTT**

# Estimated RTT

This section is rather straightforward. After a packet is sent in send_segment(), the time of transmission is logged in a list. Then when an ACK for that segment is received, there will be a lookup on the list to calculate the time elapsed and update the smoothed or estimated rtt accordingly.

Equation is as follows:
### est_rtt = alpha * est_rtt + (1 - alpha) * sample_rtt

Default values include:  
- self.est_rtt = DEFAULT_TIMEOUT
- self.alpha = 0.5
- self.RTT = DEFAULT_TIMEOUT