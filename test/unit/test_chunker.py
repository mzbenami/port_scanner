import unittest
import random

from port_scanner.chunker import *

VALID_LIST = range(LOWEST_PORT_NUMBER, HIGHEST_PORT_NUMBER + 1)

def random_sample(population, divisor=2):
    return random.sample(population, len(population) / 2)


class ChunkerTest(unittest.TestCase):

    def test_port_intersection(self):
        intersect_list = [
            ({1, 2, 3}, {1, 2, 3, 4}, {1, 2, 3}),
            ({1, 2, 3, 4}, {1, 2, 3}, {1, 2, 3}),
            ({1, 2}, {3, 4}, set([])),
            ({1, 2, 3}, {3, 4}, {3})
        ]

        for ps1, ps2, expected in intersect_list:
            result = port_set_intersection(ps1, ps2)
            self.assertEqual(expected, result)

    def test_validate_port_list_filter(self):
        too_low_port = LOWEST_PORT_NUMBER - 1
        too_high_port = HIGHEST_PORT_NUMBER + 1

        valid_sample = random_sample(VALID_LIST)

        port_list = []
        port_list.append(too_low_port)
        port_list.append(too_high_port)
        port_list.extend(valid_sample)

        result = validate_port_list(port_list)

        self.assertEqual(set(valid_sample), result)

    def test_validate_port_list_no_change(self):
        valid_sample = random_sample(VALID_LIST)
        result = validate_port_list(valid_sample)

        self.assertEqual(set(valid_sample), result)


    def test_remove_ports_from_pool(self):
        pool = set(random_sample(VALID_LIST))
        to_remove = random_sample(pool)

        self.assertGreaterEqual(len(pool.intersection(to_remove)), 1)
        remove_ports_from_pool(to_remove, pool)
        self.assertEqual(pool.intersection(to_remove), set([]))

    def test_remove_ports_with_error(self):
        pool = {1, 2, 3}
        to_remove = [4, 5, 6]

        with self.assertRaises(RemovalError):
            remove_ports_from_pool(to_remove, pool)




    def test_init_chunker(self):
        valid_set = set(VALID_LIST)
        valid_set -= FIRST_CLASS_PORTS
        valid_set -= SECOND_CLASS_PORTS

        valid_sample = set(random_sample(valid_set))
        fc_sample = set(random_sample(FIRST_CLASS_PORTS))
        sc_sample = set(random_sample(SECOND_CLASS_PORTS))

        port_list = []
        port_list.extend(valid_sample)
        port_list.extend(fc_sample)
        port_list.extend(sc_sample)
        random.shuffle(port_list)

        chunker = PortChunker(port_list)

        self.assertEqual(chunker.first_class_pool, fc_sample)
        self.assertEqual(chunker.second_class_pool, sc_sample)
        self.assertEqual(chunker.main_pool.intersection(fc_sample), set([]))
        self.assertEqual(chunker.main_pool.intersection(sc_sample), set([]))



if __name__ == "__main__":
    unittest.main()
