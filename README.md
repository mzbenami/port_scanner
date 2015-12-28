# Port Scanner

This repository consists of a package ``port_scanner`` and a console script ``portscanner`` that can be used to scan for open, closed, and filtered ports on a remote host.

Full documentation for the library can be found [here](link).

## Usage instructions for the console script:

```
$ portscanner --help
usage: portscanner [-h] [--ports PORTS] [--show-closed] HOST

positional arguments:
  HOST                  The hostname or IP address to port scan. If a hostname
                        is given which resolves to multiple addresses, only
                        one address will be scanned.

optional arguments:
  -h, --help            show this help message and exit
  --ports PORTS, -p PORTS
                        The hyphen- and/or comma-separated port list to scan.
                        e.g. '1,2-8,9,10-20' Defaults to ports 1-65535. Ports
                        outside this range will be ignored.
  --show-closed, -c     If present, closed ports are displayed.
```

## Installation

Clone this repo and ``cd`` into it, then:

```
python setup.py install
```

This will install the needed library, and make the console script ``portscanner`` available on your ``PATH``.

## Example Runs

```
$ portscanner www.google.com -p 80,443
Staring port scan of host www.google.com.

RESULTS
=======
www.google.com seems to have 2 open, 0 closed, 0 filtered, and 0 unknown ports.

PORT        STATUS
80          open
443         open
```

```
$ portscanner www.github.com -p 1-500
Staring port scan of host www.github.com.

RESULTS
=======
www.github.com seems to have 3 open, 0 closed, 497 filtered, and 0 unknown ports.

PORT        STATUS
22          open
80          open
443         open
```

```
$ portscanner 172.16.9.133 --ports 1,20-25,7 -c
Staring port scan of host 172.16.9.133.

RESULTS
=======
172.16.9.133 seems to have 1 open, 7 closed, 0 filtered, and 0 unknown ports.

PORT		    STATUS
1		        closed
7		        closed
20		      closed
21		      closed
22		      open
23		      closed
24		      closed
25		      closed
```

## How it works

The scanner is loosely reverse engineered from the popular ``nmap`` scanner's "tcp connect" option (default). Even though "tcp syn" is more efficient, it wasn't chosen because 1) Raw socket programming is more cumbersome, 2) The user would need superuser privileges, 3) Scans are generally slowest when the remote host has a large proportion of ports that don't respond at all, in which case "tcp syn" and "tcp connect" send the same amount of traffic (a single SYN packet per port).

The author (me) quickly saw that using single-threaded synchronous sockets were not an efficient option. Even for remote hosts that send "connection refused" for non-open ports, scans could take hours. Asynchronous sockets and/or multi-threading was needed. The current implementation uses single-threaded asynchronous sockets, but is designed for easy extensibility to multiple threads in the future. The ``select`` system call is used to attempt to "reap" information from groups of concurrently connecting "chunks" of ports.

``nmap`` seems to use two threads, each one sending SYNs over "chunks" of 10 to 25 ports at a time, at around .1 second intervals. This information was gleaned through wireshark. It sends ports 80 and 443 first, regardless of whether the user is interested in them. These ports also serve as the "ping test" to see whether a host is up. Then in the next two chunks it sends about 20 other popular ports (or whatever subset thereof the user is interested in) mixed in with random ports from the desired range. ``nmap`` seems to believe that ports sent earlier in the process have a better chance of obtaining accurate results, before the remote host detects and thwarts the scan.

This library also sends ports 80 and 443 in the first chunk, but only if the user is interested in them, and then sends other popular ports mixed with random ports in the next few chunks, until the popular ports are exhausted, and then the chunks can only consist of general random ports in the desired set. In this way, there is no "ping test", but the library also won't give up on a host just because 80 and 443 aren't responding (unlike nmap).

In the beginning, I thought I could concurrently open all (worst case 65535) desired ports at once, and continue to call ``select`` on all of them, until a reasonable timeout would show unreaped ports to be filtered. That didn't work for two reasons: 1) False negatives. Sites like google.com and github.com would sometimes not respond at all on ports 80 or 443 if I sent them 1000 ports at a time. 2) Open file limits. ``select`` has a limit of 1024 file desciptors it can take at a time. OSs have their own per-process limits. My Mac was set at 256. Even when I lowered chunk sizes to the range of 100s, false negatives would still happen. That's when I decided to reverse engineer ``nmap``'s algorithm, and sure enough small chunks were the way to go.

## Testing

A Makefile is provided for testing. Enjoy these targets:

``unittest``: Run unit tests on the library.

``coverage_report``: See a coverage report on teh command line.

``coverage_html``: Generate an HTML coverage report in ``coverage_html_report/``.

Current coverage is at 99%.

Only unit and not integration/system testing has been implemented so far. The ``mock`` library is used to simulate socket and other system calls. A possible route for a integration testing could be to include a Vagrant or Docker file that brings up a test host and opens, closes, or filters certain ports.
