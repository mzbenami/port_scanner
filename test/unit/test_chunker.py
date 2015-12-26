import unittest
import random
import copy

from port_scanner.chunker import *

VALID_LIST = range(LOWEST_PORT_NUMBER, HIGHEST_PORT_NUMBER + 1)


def random_sample(population, divisor=2):
    return random.sample(population, len(population) / divisor)


class ChunkerTestCase(unittest.TestCase):

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

        remove_ports_from_pool(to_remove, pool)

        self.assertEqual(pool.intersection(to_remove), set([]))

    def test_remove_ports_with_error(self):
        pool = {1, 2, 3}
        to_remove = [4, 5, 6]

        with self.assertRaises(RemovalError):
            remove_ports_from_pool(to_remove, pool)

    def test_draw_from_pool(self):
        port_pool_original = set(random_sample(VALID_LIST))
        port_pool_copy = copy.copy(port_pool_original)

        drawing_size = len(port_pool_copy) / 2
        drawing = set(draw_from_pool(port_pool_copy, drawing_size))

        # everything in the drawing was in the original pool
        self.assertEqual(drawing.intersection(port_pool_original), drawing)

        # the pool that we drew from no longer has any element in the drawing
        self.assertEqual(drawing.intersection(port_pool_copy), set([]))

    def test_draw_size_larger_than_pool(self):
        port_pool_original = set(random_sample(VALID_LIST))
        port_pool_copy = copy.copy(port_pool_original)

        drawing_size = len(port_pool_copy) * 2
        drawing = set(draw_from_pool(port_pool_copy, drawing_size))

        # the drawing is all of the original pool
        self.assertEqual(port_pool_original, drawing)

        # the pool that we drew from is now empty
        self.assertEqual(port_pool_copy, set([]))

    def test_draw_from_empty_pool(self):
        port_pool = set([])
        drawing = draw_from_pool(port_pool, 3)

        self.assertEqual(drawing, [])

    def test_draw_negative_size(self):
        port_pool = {1, 2}
        drawing = draw_from_pool(port_pool, -100)

        self.assertEqual(drawing, [])

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

    def test_get_chunk(self):
        sample_list = random_sample(VALID_LIST)
        sample_set = set(sample_list)
        chunker = PortChunker(sample_list)

        lower_bound = CHUNK_SIZE_LOWER_LIMIT
        upper_bound = CHUNK_SIZE_UPPER_LIMIT
        chunk = chunker.get_chunk(lower_bound, upper_bound)
        while chunk:
            size = len(chunk)
            self.assertLessEqual(size, upper_bound)

            chunk_set = set(chunk)
            # all elements in the chunk came from the sample set
            self.assertEqual(chunk_set.intersection(sample_set), chunk_set)

            chunk = chunker.get_chunk(lower_bound, upper_bound)

    def test_get_chunk_with_all_first_class_elements(self):
        port_list = []
        first_class_list = FIRST_CLASS_PORTS
        first_class_set = set(first_class_list)
        general_list = random_sample(VALID_LIST)

        port_list.extend(first_class_list)
        port_list.extend(general_list)

        chunker = PortChunker(port_list)
        chunk = chunker.get_chunk()
        chunk_set = set(chunk)

        self.assertEqual(chunk_set.intersection(first_class_set), chunk_set)

    def test_get_chunk_with_single_first_class_element(self):
        valid_set = set(VALID_LIST)
        valid_set -= FIRST_CLASS_PORTS
        valid_set -= SECOND_CLASS_PORTS

        port_list = []
        first_class_list = random.sample(FIRST_CLASS_PORTS, 1)
        general_list = random_sample(valid_set)

        port_list.extend(first_class_list)
        port_list.extend(general_list)

        chunker = PortChunker(port_list)
        chunk = chunker.get_chunk()

        self.assertEqual(len(chunk), 1)
        self.assertEqual(chunk, first_class_list)

    def test_get_chunk_invalid_bounds(self):

        def test_with_bounds(port_list, lower, upper):
            chunker = PortChunker(port_list)

            with self.assertRaises(ChunkBoundsError):
                chunker.get_chunk(lower, upper)

        port_list = random_sample(VALID_LIST)
        test_with_bounds(port_list, -1, 5)
        test_with_bounds(port_list, 6, 3)

    def test_random_chunk_size(self):
        lower = 3
        upper = 6

        size = random_chunk_size(lower, upper)
        self.assertLessEqual(size, upper)
        self.assertGreaterEqual(size, lower)


    def test_random_chunk_invalid_bound(self):
        lower = 6
        upper = 3

        with self.assertRaises(ChunkBoundsError):
            random_chunk_size(lower, upper)

if __name__ == "__main__":
    unittest.main()
