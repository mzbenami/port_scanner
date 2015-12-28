"""This module provides functions and a class ``PortScanner``
for scanning a collection of ports on a remote host.
"""
import select
import time
import socket

from port_scanner.values import RESULT_FILTERED
from port_scanner.probe import PortProbe
from port_scanner.chunker import PortChunker

# interval at which to probe chunks of ports together
INTERVAL_TIME = 0.11


class InvalidHostError(Exception):
    def __init__(self, host):
        self.message = '%s is an invalid host or IP address' % host


def reverse_port_chunk(port_chunk):
    """Return a port_chunk(list) in reverse order.
    """
    return port_chunk[::-1]


class PortScanner(object):
    """This class takes a remote host and a collection of ports and scans
    and scans the ports for their status.

    Args:
        host(str): The hostname or IP address of the remote host. If a hostname
            is given and it resolves to multiple addresses, only one address is used.
            If a hostname is given that doesn't resolve, initialization fails.
        port_list(collection): The collection of port numbers (integers) to scan.

    Attributes:
        results_map(dict): A dictionary mapping ports to their status codes
            populated during a call to ``run()``.

    Raises:
        InvalidHostError: If hostname doesn't resolve.
    """
    def __init__(self, host, port_list):
        try:
            self.address = socket.gethostbyname(host)
        except socket.gaierror:
            raise InvalidHostError(host)

        self.port_list = port_list
        self.results_map = {}

    def launch_probes(self, port_chunk):
        """Launch probes on a given port chunk.

        Return a map of underlying file descriptors to ``PortProbe``s.
        If a result for the port is already in the ``results_map``, a
        new probe is not created.

        Args:
            port_chunk(list): List of ports to probe at one time.

        Returns:
            fd_map(dictionary): Map of underlying file descriptors to ``PortProbe``s.
        """
        fd_map = {}

        for port in port_chunk:
            if port not in self.results_map \
                    or self.results_map[port] == RESULT_FILTERED:
                probe = PortProbe(self.address, port)
                fd_map[probe.file_no] = probe

        return fd_map

    def poll(self, port_chunk, timeout):
        """Launch probes for given port chunk, and check their
        status with ``select.select``. Populate ``results_map``
        with results.

        Args:
            port_chunk(list): List of ports to poll.
            timeout(float): Amount of total time to spend in this
                method. Time is either used entirely with calls to
                ``select.select`` or used sleeping if ``select.select``
                returns information on all ports in the chunk.
        """
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

    def run(self, interval_time=INTERVAL_TIME):
        """Clear the results map and start a new scan.

        Ports from the instance's ``port_list`` are chunked,
        and each chunk is polled twice, the second time in reverse order.

        Keyword Args:
            interval_time(float): The time to wait between each poll.
        """
        self.clear()

        port_chunker = PortChunker(self.port_list)
        port_chunk = port_chunker.get_chunk()
        while port_chunk:
            self.poll(port_chunk, interval_time)
            reversed_chunk = reverse_port_chunk(port_chunk)
            self.poll(reversed_chunk, interval_time)

            port_chunk = port_chunker.get_chunk()

        return self.results_map

    def clear(self):
        """Clear the results map.
        """
        self.results_map.clear()
