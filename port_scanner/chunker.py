"""This module provides functions and a class ``PortChunker`` for feeding chunks of ports
to a port scanner.
"""
import random

CHUNK_SIZE_LOWER_LIMIT = 10
CHUNK_SIZE_UPPER_LIMIT = 20

LOWEST_PORT_NUMBER = 1
HIGHEST_PORT_NUMBER = 65335

FIRST_CLASS_PORTS = {80, 443}
SECOND_CLASS_PORTS = {139, 53, 23, 111, 995,
                      22, 993, 143, 135, 110,
                      445, 587, 25, 199, 113,
                      21, 256, 554}


class RemovalError(Exception):
    def __init__(self, port):
        self.message = '%d not in port pool. It may have already been removed.' % port


class ChunkBoundsError(Exception):
    def __init__(self, lower, upper):
        self.message = 'Bounds must be such that 0 <= lower_bound <= upper_bound\n'
        self.message += 'Received lower bound: %d, upper bound: %d' % (lower, upper)


def bounds_are_valid(lower, upper):
    if lower >= 0 and lower <= upper:
        return True

    return False


def port_set_intersection(port_set_1, port_set_2):
    """Return the intersection of two sets of ports(integers).
    """
    return port_set_1.intersection(port_set_2)


def random_chunk_size(lower_bound, upper_bound):
    """Return a random integer between lower_bound and upper_bound.

    Raises:
        ChunkBoundsError: if bounds are invalid.
    """
    if not bounds_are_valid(lower_bound, upper_bound):
        raise ChunkBoundsError(lower_bound, upper_bound)

    return random.randint(lower_bound, upper_bound)


def port_is_valid(port):
    return port >= LOWEST_PORT_NUMBER and port <= HIGHEST_PORT_NUMBER


def validate_port_list(port_list):
    """Filter out invalid (out of bounds) ports from list.
    """
    port_pool = set()
    for port in port_list:
        if port_is_valid(port):
            port_pool.add(port)

    return port_pool


def remove_ports_from_pool(ports_to_remove, port_pool):
    """Remove ports from a pool(set) of ports.

    Args:
        ports_to_remove(collection): iterable collection of ports to remove.
        port_pool(set): pool to remove from.

    Raises:
        RemovalError: if a port isn't in the pool to begin with.
    """
    try:
        for port in ports_to_remove:
            port_pool.remove(port)
    except KeyError:
        raise RemovalError(port)


def draw_from_pool(port_pool, size):
    """Return a random sample of ports from a pool,
    and remove those ports from the pool.

    Args:
        port_pool(set): The pool of ports to draw from.
        size(int): The desired size of the drawing.
            If size is bigger than the pool, the pool will be completely drained.

    Returns:
        Random sample of ports from the pool.
    """
    if size < 0:
        size = 0

    size = min(size, len(port_pool))
    drawing = random.sample(port_pool, size)
    remove_ports_from_pool(drawing, port_pool)
    return drawing


def port_pool_is_empty(port_pool):
    """Check whether a port pool is empty.
    """
    return len(port_pool) == 0


class PortChunker(object):
    """This object is initialized with a collection of ports(integers)
    that it splits up into     distinct non-overlapping pools(sets).
    The member method ``get_chunk()`` draws from the pools according to preferences.
    Designed to be called by ``port_scanner.scanner.PortScanner``
    to scan chunks of ports at a time.

    Args:
        port_list(collection): Collection of ports to form the basis of the pools.

    Attributes:
        fist_class_pool: A pool of very popular ports
            that a scanner would want to check first.
        second_class_pool: A pool of popular ports
            that a scanner would want to check early in the process.
        main_pool: A pool of ports that aren't first class or second class.

    """
    def __init__(self, port_list):
        port_pool = validate_port_list(port_list)

        self.first_class_pool = port_set_intersection(port_pool, FIRST_CLASS_PORTS)
        port_pool -= self.first_class_pool

        self.second_class_pool = port_set_intersection(port_pool, SECOND_CLASS_PORTS)
        port_pool -= self.second_class_pool

        self.main_pool = port_pool

    def get_chunk(self,
                  lower_bound=CHUNK_SIZE_LOWER_LIMIT,
                  upper_bound=CHUNK_SIZE_UPPER_LIMIT):
        """Return a randomized chunk(list) of ports from the various instance pools.
        Ensure ports in chunk are no longer in the pool drawn from.

        Args:
            lower_bound: The suggested lower bound on the size of a chunk from the main pool.
                Also the suggested upper bound on a chunk drawing from a first or second-class pool.
            upper_bound: The hard upper bound on the size of any chunk returned.

        Returns:
             A randomized chunk(list) of ports from the various instance pools.
        """
        if not bounds_are_valid(lower_bound, upper_bound):
            raise ChunkBoundsError(lower_bound, upper_bound)

        # first class ports get chunks all to themselves
        if not port_pool_is_empty(self.first_class_pool):
            # drawing size from first class pool should be small (at most lower_bound)
            drawing = draw_from_pool(self.first_class_pool, lower_bound)
            return drawing

        # second class ports get priority, but can be mixed in with ports from the main pool
        if not port_pool_is_empty(self.second_class_pool):
            # drawing size from second class pool should make up at most half of the returned chunk
            drawing = draw_from_pool(self.second_class_pool, lower_bound / 2 + 1)
            remaining_size = lower_bound - len(drawing)

            if remaining_size > 0:
                drawing += draw_from_pool(self.main_pool, remaining_size)
                random.shuffle(drawing)

            return drawing

        # only get here when first and second class ports are exhausted
        if not port_pool_is_empty(self.main_pool):
            desired_chunk_size = random_chunk_size(lower_bound, upper_bound)
            drawing = draw_from_pool(self.main_pool, desired_chunk_size)
            return drawing
