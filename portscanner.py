import sys
import socket
import threading
from datetime import datetime

# Validate the IP address format
def validIP(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Scan a specific port on the target IP
def scan(target, port):
    global open_ports
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(0.1)
    result = s.connect_ex((target, port))
    if result == 0:
        open_ports.append(port)  # Collect open ports instead of printing each
    s.close()

port_services = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle Database",
    1701: "L2TP",
    1723: "PPTP",
    1812: "RADIUS Authentication",
    1813: "RADIUS Accounting",
    2049: "NFS",
    3306: "MySQL Database",
    3389: "RDP",
    5432: "PostgreSQL Database",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternative",
    8443: "HTTPS Alternative",
    8888: "HTTP Alternative",
    10000: "Webmin",
    25565: "Minecraft Server",
    27017: "MongoDB"
}

# Validate IP and handle command-line arguments

if (len(sys.argv) == 2 or len(sys.argv) == 4):
    ipValidation = validIP(sys.argv[1])
    if ipValidation:
        target = socket.gethostbyname(sys.argv[1])
    else:
        print("Invalid IP address")
        sys.exit()
else:
    print("Invalid number of arguments")
    print("Syntax: python3 portscanner.py <ip> [-s <filename>]")
    sys.exit()

# Store the open ports
open_ports = []

start_time = datetime.now()
print("=" * 50)
print("Scanning target: " + target)
print("Time started: " + str(start_time))
print("=" * 50)

threads = []

# Use threading to scan ports concurrently
try:
    for port in range(1, 65536):
        thread = threading.Thread(target=scan, args=(target, port))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit()
except socket.gaierror:
    print("Hostname could not be resolved.")
    sys.exit()

# End of scan
finish_time = datetime.now()
duration_time = finish_time - start_time

# Format output of open ports
print("\n" + "_" * 50)
print("\nPORTS\tSERVICE")
print("_" * 50)

if open_ports:
    open_ports.sort()  # Sort the list of open ports
    for port in open_ports:
        service = port_services.get(port, "Unknown Service")
        print(f"{port}\t{service}")
else:
    print("No open ports found.")

print("\n" + "=" * 50)
print("Number of open ports: " + str(len(open_ports)))
print("\nTime finished: " + str(finish_time))
print("Time duration: " + str(duration_time))
print("=" * 50)

if (len(sys.argv) == 4):
    try:
        filename = sys.argv[3]
        port_file = open(filename, "w")
        port_file.write("Scanned target: " + target + "\n\n")
        port_file.write("_" * 40 + "\n")
        port_file.write("PORTS\tSERVICE\n")
        port_file.write("_" * 40 + "\n")
        for port in open_ports:
            service = port_services.get(port, "Unkown Service")
            port_file.write(f"{port}\t{service}\n")
        port_file.close()

    except:
        print("An error occurred while writing to file.")
        if (not port_file.closed()):
            port_file.close()