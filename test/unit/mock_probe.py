from port_scanner.values import *
import random

counter = 2

def get_next_counter():
    global counter
    counter += 1
    return counter

class MockProbe(object):
    def __init__(self, ip_addr, port):
        self.file_no = get_next_counter()
        self.port = port
        self.result = RESULT_UNKNOWN

    def close(self):
        pass

    def analyze(self):
        if self.result is not RESULT_UNKNOWN:
            return self.result

        possible_results = [RESULT_OPEN, RESULT_FILTERED, RESULT_CLOSED]
        return possible_results[random.randint(0, len(possible_results) - 1)]
