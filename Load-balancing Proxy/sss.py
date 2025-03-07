def process_client_data(self, fd):
    """
    Receives up to 4096 bytes from the client associated with the given file descriptor,
    aggregates the incoming data, and once complete HTTP requests are detected,
    dispatches them to the backend server.
    """
    client_socket = self.fd_to_socket[fd]
    try:
        # Attempt to receive a chunk of data from the client.
        data = client_socket.recv(4096)
        if not data:
            # If no data is returned, the client has likely closed the connection.
            self._close_connection(fd)
            return
        # Append the newly received data to the client's existing buffer.
        self.client_buffers[fd] += data
    except ConnectionResetError:
        # Close the connection if the client unexpectedly resets it.
        self._close_connection(fd)
        return

    # Extract complete HTTP requests from the accumulated buffer.
    complete_requests, remaining_buffer = self._parse_http_requests(self.client_buffers[fd])
    self.client_buffers[fd] = remaining_buffer  # Retain any partial data for future reads.

    # Forward each fully parsed request to the backend server.
    for request in complete_requests:
        self._forward_new_request(fd, request)
