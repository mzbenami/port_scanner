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
    return port_set_1.intersection(port_set_2)


def random_chunk_size(lower_bound, upper_bound):
    if not bounds_are_valid(lower_bound, upper_bound):
        raise ChunkBoundsError(lower_bound, upper_bound)

    return random.randint(lower_bound, upper_bound)


def port_is_valid(port):
    return port >= LOWEST_PORT_NUMBER and port <= HIGHEST_PORT_NUMBER


def validate_port_list(port_list):
    port_pool = set()
    for port in port_list:
        if port_is_valid(port):
            port_pool.add(port)

    return port_pool


def remove_ports_from_pool(ports_to_remove, port_pool):
    try:
        for port in ports_to_remove:
            port_pool.remove(port)
    except KeyError:
        raise RemovalError(port)


def draw_from_pool(port_pool, size):
    if size < 0:
        size = 0

    size = min(size, len(port_pool))
    drawing = random.sample(port_pool, size)
    remove_ports_from_pool(drawing, port_pool)
    return drawing


def port_pool_is_empty(port_pool):
    return len(port_pool) == 0


class PortChunker(object):

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

        if not bounds_are_valid(lower_bound, upper_bound):
            raise ChunkBoundsError(lower_bound, upper_bound)

        if not port_pool_is_empty(self.first_class_pool):
            # drawing size from first class pool should be small (at most lower_bound)
            drawing = draw_from_pool(self.first_class_pool, lower_bound)
            return drawing

        if not port_pool_is_empty(self.second_class_pool):
            # drawing size from second class pool should make up at most half of the returned chunk
            drawing = draw_from_pool(self.second_class_pool, lower_bound / 2 + 1)
            remaining_size = lower_bound - len(drawing)

            if remaining_size > 0:
                drawing += draw_from_pool(self.main_pool, remaining_size)
                random.shuffle(drawing)

            return drawing

        if not port_pool_is_empty(self.main_pool):
            desired_chunk_size = random_chunk_size(lower_bound, upper_bound)
            drawing = draw_from_pool(self.main_pool, desired_chunk_size)
            return drawing
