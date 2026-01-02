# Import socket module for network communication
import socket

# Import datetime to record scan start and end time
from datetime import datetime


def scan_port(target_ip, port):
    """
    Attempts to connect to a specific TCP port on the target IP.
    If connection is successful, the port is open.

    Args:
        target_ip (str): IP address of the target
        port (int): Port number to scan

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # Create a TCP socket (IPv4 + TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set timeout to avoid hanging on closed/filtered ports
        sock.settimeout(0.5)

        # connect_ex() returns 0 if connection is successful
        result = sock.connect_ex((target_ip, port))

        # Close socket after attempting connection
        sock.close()

        # If result is 0, port is open
        return result == 0

    except socket.error:
        # If any socket error occurs, treat port as closed
        return False


def main():
    """
    Main function that:
    - Takes user input
    - Resolves hostname to IP
    - Scans a range of ports
    - Displays results
    """

    # Display program banner
    print("=" * 50)
    print("        Simple Port Scanner (Python)")
    print("=" * 50)

    # Get target hostname or IP from user
    target = input("Enter target IP or hostname: ")

    try:
        # Resolve hostname to IP address
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        # If hostname resolution fails
        print("Error: Invalid hostname or unreachable target.")
        return

    # Get port range from user
    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
    except ValueError:
        print("Error: Ports must be integers.")
        return

    # Display scan information
    print("\nScanning Target:", target_ip)
    print("Scan started at:", datetime.now())
    print("-" * 50)

    # List to store open ports
    open_ports = []

    # Loop through each port in the given range
    for port in range(start_port, end_port + 1):

        # Check if current port is open
        if scan_port(target_ip, port):
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)

    # Scan completed
    print("-" * 50)
    print("Scan completed at:", datetime.now())

    # Display scan results
    if open_ports:
        print("\nOpen Ports Found:")
        for port in open_ports:
            print(f"- Port {port}")
    else:
        print("\nNo open ports found.")

    print("\nNote: Scan only systems you own or have permission to test.")


# Entry point of the program
# Ensures main() runs only when this file is executed directly
if __name__ == "__main__":
    main()
