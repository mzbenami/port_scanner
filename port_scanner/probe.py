import socket
import struct
import os

from errno import EALREADY, EINPROGRESS, EWOULDBLOCK, EINVAL, \
     ENOTCONN, EISCONN, EBADF,  \
     ETIMEDOUT, ECONNREFUSED, errorcode

from port_scanner.values import RESULT_CLOSED, RESULT_FILTERED, RESULT_OPEN, RESULT_UNKNOWN


def connect(sock, address):
    # adapted from asyncore.py
    err = sock.connect_ex(address)
    if err in (0, EISCONN, EINPROGRESS, EALREADY, EWOULDBLOCK) \
            or err == EINVAL and os.name in ('nt', 'ce'):
        return
    else:
        raise socket.error(err, errorcode[err])


def create_tcp_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class PortProbe(object):

    def __init__(self, ip_addr, port):
        self.socket = create_tcp_socket()
        self.socket.setblocking(0)

        # send RST on close() instead of FIN handshake
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                               struct.pack('ii', 1, 0))

        connect(self.socket, (ip_addr, port))

        self.file_no = self.socket.fileno()
        self.port = port
        self.result = RESULT_UNKNOWN

    def close(self):
        self.socket.close()

    def analyze(self):
        if self.result is not RESULT_UNKNOWN:
            return self.result

        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err == 0:
            try:
                self.socket.getpeername()
            except socket.error as se:
                if se.errno == ENOTCONN:
                    self.result = RESULT_UNKNOWN
                elif se.errno == EINVAL:
                    self.result = RESULT_OPEN
                else:
                    raise se
            else:
                self.result = RESULT_OPEN



        elif err == ETIMEDOUT:
            self.result = RESULT_FILTERED

        elif err == ECONNREFUSED:
            self.result = RESULT_CLOSED

        return self.result
