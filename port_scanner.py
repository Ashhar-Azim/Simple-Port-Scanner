import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(target_ip, port):
    """
    Attempts to connect to a TCP port on the target IP.
    Returns True if the port is open, False otherwise.
    """
    try:
        # Create a TCP socket (IPv4, TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Short timeout to avoid blocking threads
        sock.settimeout(0.5)

        # connect_ex returns 0 if connection succeeds
        result = sock.connect_ex((target_ip, port))

        # Close the socket after attempt
        sock.close()

        return result == 0

    except socket.error:
        return False


def main():
    print("=" * 60)
    print("        Multithreaded Port Scanner (Python)")
    print("=" * 60)

    # Get target from user
    target = input("Enter target IP or hostname: ")

    try:
        # Resolve hostname to IP address
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Invalid hostname.")
        return

    # Get port range
    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
    except ValueError:
        print("Error: Ports must be numbers.")
        return

    # Limit number of threads (important for stability)
    MAX_THREADS = 100

    print("\nScanning target:", target_ip)
    print("Scan started at:", datetime.now())
    print("-" * 60)

    open_ports = []

    # ThreadPoolExecutor manages thread creation efficiently
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        # Submit scan_port tasks to thread pool
        future_to_port = {
            executor.submit(scan_port, target_ip, port): port
            for port in range(start_port, end_port + 1)
        }

        # Process results as threads complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]

            try:
                if future.result():
                    print(f"[+] Port {port} is OPEN")
                    open_ports.append(port)
            except Exception:
                # Catch unexpected thread errors
                pass

    print("-" * 60)
    print("Scan completed at:", datetime.now())

    # Display results
    if open_ports:
        print("\nOpen Ports Found:")
        for port in sorted(open_ports):
            print(f"- Port {port}")
    else:
        print("\nNo open ports found.")

    print("\n⚠️  Ethical Reminder: Scan only systems you own or have permission to test.")


# Program entry point
if __name__ == "__main__":
    main()
