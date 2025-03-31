data_buffer = []

def add_to_buffer(packet):
    """
    Add a packet to the end of the data_buffer. Will innately sort the data buffer and ignore repeats
    """


    match(len(data_buffer)):
        case 0:
            data_buffer.append(packet)

        case 1:
            if packet < data_buffer[0]:
                data_buffer.insert(0,packet)
            else:
                data_buffer.append(packet)
            
        case _:
            for i, buffered_packet in enumerate(data_buffer):
                if i+1 < len(data_buffer):
                    # If packet seq fits between this buffered packet and the next one
                    if buffered_packet < packet and packet < data_buffer[i+1]:
                        data_buffer.insert(i+1, packet)
                        return
            if(data_buffer[len(data_buffer) - 1] < packet):
                data_buffer.append(packet)
            


print(data_buffer)

add_to_buffer(1)
print(data_buffer)

add_to_buffer(3)
print(data_buffer)

add_to_buffer(5)
print(data_buffer)

add_to_buffer(2)
print(data_buffer)

add_to_buffer(4)
print(data_buffer)

add_to_buffer(5)
print(data_buffer)
