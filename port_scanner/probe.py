"""This module provides functions and a class ``PortProbe`` to connect
over a single TCP socket on a specified port, and determine the status of the
port on the host on the otherside.
"""
import socket
import struct
import os

from errno import EALREADY, EINPROGRESS, EWOULDBLOCK, EINVAL, \
     ENOTCONN, EISCONN, EBADF,  \
     ETIMEDOUT, ECONNREFUSED, errorcode

from port_scanner.values import RESULT_CLOSED, RESULT_FILTERED, RESULT_OPEN, RESULT_UNKNOWN


def connect(sock, address):
    """Asynchronously connect over a provided TCP socket.

    Args:
        sock(socket.socket): Socket to connect over.
        address(tuple): (ip_addr, port) tuple to connect to.

    Raises:
        socket.error: If error encountered not normally found with
            asynchronous connections.
    """
    # adapted from asyncore.py
    err = sock.connect_ex(address)
    if err in (0, EISCONN, EINPROGRESS, EALREADY, EWOULDBLOCK) \
            or err == EINVAL and os.name in ('nt', 'ce'):
        return
    else:
        raise socket.error(err, errorcode[err])


def create_tcp_socket():
    """TCP socket factory.
    """
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def setup_tcp_socket(sock):
    """Set up a TCP socket for asynchronous calls,
    and to close connections with RST instead of FIN handshakes.
    """
    sock.setblocking(0)
    # send RST on close() instead of FIN handshake
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack('ii', 1, 0))


class PortProbe(object):
    """This class connects over a socket on initialization,
    and provides an ``analyze()`` method to determine the status of
    the port on the other side.

    Args:
        ip_addr(str): IP address of host to connect to. If a hostname is given
            instead of an IP address, behavior is undefined.
        port(int): Port to connect to.

    Attributes:
        file_no(int): The file descriptor of the associated socket.
        port(int): The remote port of the associated socket.
    """

    def __init__(self, ip_addr, port):
        self.socket = create_tcp_socket()
        setup_tcp_socket(self.socket)
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
