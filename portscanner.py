#! /usr/bin/python

import sys
import argparse

from port_scanner.scanner import PortScanner
from port_scanner.values import *


def exit_failure(message):
    sys.stderr.write(message)
    sys.stderr.flush()
    sys.exit(1)


def syntax_error_msg(section):
    return '%s uses invalid syntax for port list.\n' % section


def port_list_from_string(port_string):
    """Convert a comma- and hyphen-separated string of integers
        to a list of unique integers.
    """
    port_list = []
    comma_separated = port_string.split(',')
    for section in comma_separated:
        if '-' not in section:
            try:
                port_num = int(section)
                port_list.append(port_num)
            except ValueError:
                exit_failure(syntax_error_msg(section))
        else:
            lower_and_upper = section.split('-')
            try:
                lower = int(lower_and_upper[0])
                upper = int(lower_and_upper[1])
            except (IndexError, ValueError):
                exit_failure(syntax_error_msg(section))

            if lower > upper:
                exit_failure('Section %s is an invalid range.\n' % section)

            port_list.extend(range(lower, upper + 1))

    return list(set(port_list))


def handle_args():
    """Parse command line argruments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('host', metavar='HOST',
                        help='The hostname or IP address to port scan. ' +
                             'If a hostname is given which resolves to multiple addresses, ' +
                             'only one address will be scanned.')
    parser.add_argument('--ports', '-p',
                        default='1-65535',
                        help='The hyphen- and/or comma-separated port list to scan.\n' +
                             'e.g. \'1,2-8,9,10-20\'\n' +
                             'Defaults to ports 1-65535.')

    args = parser.parse_args()
    return args


def print_results(host, results_map, dont_detail=[RESULT_FILTERED]):
    """Print scan results to stdout.""
    Args:
        host(str): The host that was scanned.
        results_map(dict): Dictionary of (port, result) mappings
            as found in a port_scanner.scanner.PortScanner object after a scan.

    Keyword Args:
        dont_detail(list): List of RESULT types (integers)
            to not print out in detail.
    """
    counts = {
        RESULT_OPEN: 0,
        RESULT_FILTERED: 0,
        RESULT_CLOSED: 0,
        RESULT_UNKNOWN: 0
    }

    words = {
        RESULT_OPEN: 'open',
        RESULT_FILTERED: 'filtered',
        RESULT_CLOSED: 'closed',
        RESULT_UNKNOWN: 'unknown'
    }

    results_str_list = []
    for port in results_map:
        result = results_map[port]
        counts[result] += 1
        if result not in dont_detail:
            results_str_list.append('%s\t\t%s' % (port, words[result]))

    print "RESULTS"
    print "======="
    print '%s seems to have %d open, %d closed, %d filtered, and %d unknown ports.' \
        % (host, counts[RESULT_OPEN],
           counts[RESULT_CLOSED],
           counts[RESULT_FILTERED],
           counts[RESULT_UNKNOWN])
    print
    print 'PORT\t\tSTATUS'
    print '\n'.join(results_str_list)


def main():
    # parse args
    args = handle_args()
    host = args.host
    port_list = port_list_from_string(args.ports)

    print 'Staring port scan of host %s.\n' % host

    # run scan
    ps = PortScanner(host, port_list)
    ps.run()

    # print results
    print_results(host, ps.results_map)

if __name__ == "__main__":
    main()
