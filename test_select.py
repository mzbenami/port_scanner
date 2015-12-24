import select
import socket
import struct
import os
import time
import resource
import random
import copy

from errno import EALREADY, EINPROGRESS, EWOULDBLOCK, ECONNRESET, EINVAL, \
     ENOTCONN, ESHUTDOWN, EINTR, EISCONN, EBADF, ECONNABORTED, EPIPE, EAGAIN, \
     ETIMEDOUT, ECONNREFUSED, errorcode

FIRST_CLASS_PORTS = {80, 443}
SECOND_CLASS_PORTS = {139, 53, 23, 111, 995,
                      22, 993, 143, 135, 110,
                      445, 587, 25, 199, 113,
                      21, 256, 554}

RESULT_UNKNOWN = 0
RESULT_OPEN = 1
RESULT_CLOSED = 2
RESULT_FILTERED = 3

CHUNK_SIZE_LOWER_LIMIT = 10
CHUNK_SIZE_UPPER_LIMIT = 20

LOWEST_PORT_NUMBER = 1
HIGHEST_PORT_NUMBER = 65335


def port_set_intersection(port_set_1, port_set_2):
    return port_set_1.intersection(port_set_2)

def random_chunk_size(lower_bound, upper_bound):
    return random.randint(lower_bound, upper_bound)

def port_is_valid(port):
    return port >= LOWEST_PORT_NUMBER and port <= HIGHEST_PORT_NUMBER


class PortChunker(object):

    def __init__(self, port_list):
        port_pool = set(port_list)

        self.first_class_pool = port_set_intersection(port_pool, FIRST_CLASS_PORTS)
        port_pool -= self.first_class_pool

        self.second_class_pool = port_set_intersection(port_pool, SECOND_CLASS_PORTS)
        port_pool -= self.second_class_pool

        self.main_pool = port_pool

    def remove_ports_from_pool(self, ports_to_remove, port_pool):
        for port in ports_to_remove:
            port_pool.remove(port)

    def draw_from_pool(self, port_pool, size):
        size = min(size, len(port_pool))
        drawing = random.sample(port_pool, size)
        self.remove_ports_from_pool(drawing, port_pool)

        return drawing

    def port_pool_is_empty(self, port_pool):
        return len(port_pool) == 0

    def get_chunk(self,
                  lower_bound=CHUNK_SIZE_LOWER_LIMIT,
                  upper_bound=CHUNK_SIZE_UPPER_LIMIT):

        if not self.port_pool_is_empty(self.first_class_pool):
            drawing = self.draw_from_pool(self.first_class_pool, lower_bound)
            return drawing

        if not self.port_pool_is_empty(self.second_class_pool):
            drawing = self.draw_from_pool(self.second_class_pool, lower_bound / 2)
            remaining_size = lower_bound - len(drawing)
            if remaining_size > 0:
                drawing += self.draw_from_pool(self.main_pool, remaining_size)
                random.shuffle(drawing)

            return drawing

        if not self.port_pool_is_empty(self.main_pool):
            desired_chunk_size = random_chunk_size(lower_bound, upper_bound)
            drawing = self.draw_from_pool(self.main_pool, desired_chunk_size)
            return drawing


class PortProbe(object):

    def __init__(self, ip_addr, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack('ii', 1, 0))

        self.connect(self.socket, (ip_addr, port))

        self.file_no = self.socket.fileno()
        self.port = port
        self.result = RESULT_UNKNOWN

    def connect(self, sock, address):
        #adapted from asyncore.py
        err = sock.connect_ex(address)
        if err in (EINPROGRESS, EALREADY, EWOULDBLOCK) \
        or err == EINVAL and os.name in ('nt', 'ce'):
            return
        if err in (0, EISCONN):
            pass
        else:
            raise socket.error(err, errorcode[err])

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
                if se.errno in [ENOTCONN, EINVAL]:
                    return RESULT_UNKNOWN
                raise se

            self.result = RESULT_OPEN

        elif err == ETIMEDOUT:
            self.result = RESULT_FILTERED

        elif err == ECONNREFUSED:
            self.result = RESULT_CLOSED

        return self.result


class PortScanner(object):

    def __init__(self, address, port_list):
        self.address = address
        self.port_list = port_list
        self.results_map = {}

    def launch_probes(self, port_chunk):
        fd_map = {}

        for port in port_chunk:
            if port not in self.results_map \
                or self.results_map[port] == RESULT_FILTERED:
                    probe = PortProbe(self.address, port)
                    fd_map[probe.file_no] = probe

        return fd_map

    def poll(self, port_chunk, timeout):
        fd_map = self.launch_probes(port_chunk)

        r = {}; e = {}
        w = set(fd_map.keys())

        while timeout > 0.0 and len(w) > 0:
            start_time = time.time()
            r2, w2, e2 = select.select(r, w, e, timeout)
            timeout -= time.time() - start_time

            for reaped in w2:
                probe = fd_map[reaped]
                self.results_map[probe.port] = probe.analyze()

                probe.close()
                w.remove(reaped)

        for unreaped in w:
            probe = fd_map[unreaped]
            self.results_map[probe.port] = RESULT_FILTERED

            probe.close()

        if timeout > 0:
            time.sleep(timeout)

    def reverse_port_chunk(self, port_chunk):
        return port_chunk[::-1]

    def run(self, interval_time=0.11):
        self.results_map.clear()
        port_chunker = PortChunker(self.port_list)

        port_chunk = port_chunker.get_chunk()
        while port_chunk:
            self.poll(port_chunk, interval_time)

            reversed_chunk = self.reverse_port_chunk(port_chunk)
            self.poll(reversed_chunk, interval_time)

            port_chunk = port_chunker.get_chunk()


port_list = range(1, 65535)
IP_ADDR = '172.16.9.133'

#ps = PortScanner(IP_ADDR, port_list)
#ps.run()



