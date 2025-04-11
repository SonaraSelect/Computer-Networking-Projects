import struct

# Constants for the project
MAX_LEN = 200  # Maximum packet length ORIGINAL: 1400
MSS = MAX_LEN - struct.calcsize("!IIIIH")  # Maximum Segment Size (based on Packet header size)

# Window variables
WINDOW_SIZE = MSS * 32  # Sliding window size (32 packets)
WINDOW_INITIAL_WINDOW_SIZE = MSS  # Initial congestion window size
WINDOW_INITIAL_SSTHRESH = MSS * 64  # Initial slow start threshold

# Timeout for retransmissions in seconds
DEFAULT_TIMEOUT = 3

# Max TCP buffer
MAX_NETWORK_BUFFER=65535