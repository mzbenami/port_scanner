import sys
from port_scanner import PortScanner

ip_addr = sys.argv[1]
print ip_addr
port_list = range(20, 31)

ps = PortScanner(ip_addr, port_list)
ps.run()