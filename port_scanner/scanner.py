import select
import time
import socket

from port_scanner.values import RESULT_FILTERED
from port_scanner.probe import PortProbe
from port_scanner.chunker import PortChunker


class InvalidHostError(Exception):
    def __init__(self, host):
        self.message = '%s is an invalid host or IP address' % host


class PortScanner(object):

    def __init__(self, host, port_list):
        try:
            self.address = socket.gethostbyname(host)
        except socket.gaierror:
            raise InvalidHostError(host)

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
