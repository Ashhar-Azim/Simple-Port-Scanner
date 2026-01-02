
---

## port_scanner.py (working beginner code)

```python
import socket
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def main():
    print("=" * 50)
    print("Simple Port Scanner")
    print("=" * 50)

    target = input("Enter target IP or hostname: ")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid hostname.")
        return

    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    print("\nScanning target:", target_ip)
    print("Scan started at:", datetime.now())
    print("-" * 50)

    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)

    print("-" * 50)
    print("Scan completed at:", datetime.now())

    if open_ports:
        print("\nOpen Ports Found:")
        for port in open_ports:
            print(f"- Port {port}")
    else:
        print("\nNo open ports found.")

if __name__ == "__main__":
    main()
