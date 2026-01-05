"""
Multithreaded Port Scanner
--------------------------
Author  : Ashhar
Purpose : Scan a target host for open TCP ports using multithreading
Note    : For educational and authorized testing only
"""

# =========================
#        IMPORTS
# =========================

# Socket module is used for low-level network communication
import socket

# datetime is used to record scan start and end time
from datetime import datetime

# ThreadPoolExecutor allows concurrent execution of port scans
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================
#     PORT SCAN FUNCTION
# =========================

def scan_port(target_ip, port):
    """
    Attempts to establish a TCP connection to a given port.

    Parameters:
        target_ip (str): IP address of the target system
        port (int): Port number to scan

    Returns:
        bool: True if port is open, False otherwise
    """

    try:
        # Create a socket using:
        # AF_INET     -> IPv4
        # SOCK_STREAM -> TCP protocol
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout so threads do not block indefinitely
        sock.settimeout(0.5)

        # Attempt connection to target port
        # connect_ex() returns:
        # 0 -> success (port open)
        # non-zero -> failure (port closed/filtered)
        result = sock.connect_ex((target_ip, port))

        # Always close the socket to free system resources
        sock.close()

        # Return True only if port is open
        return result == 0

    except socket.error:
        # Any socket-related error is treated as a closed port
        return False


# =========================
#         MAIN LOGIC
# =========================

def main():
    """
    Main program flow:
    - Accept user input
    - Resolve hostname to IP
    - Scan ports concurrently
    - Display scan results
    """

    # Program banner
    print("=" * 65)
    print("        Multithreaded Port Scanner (Python)")
    print("=" * 65)

    # -------------------------
    #   USER INPUT
    # -------------------------

    # Get target hostname or IP from user
    target = input("Enter target IP or hostname: ")

    try:
        # Convert hostname to IP address
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        # Hostname resolution failed
        print("Error: Invalid hostname or target unreachable.")
        return

    # Get port range from user
    try:
        start_port = int(input("Enter start port: "))
        end_port   = int(input("Enter end port  : "))
    except ValueError:
        # Input validation for ports
        print("Error: Port numbers must be integers.")
        return

    # -------------------------
    #   SCAN CONFIGURATION
    # -------------------------

    # Maximum number of concurrent threads
    # Higher values increase speed but may overload the system
    MAX_THREADS = 100

    # List to store open ports
    open_ports = []

    # Display scan details
    print("\nScanning Target :", target_ip)
    print("Port Range     :", f"{start_port} - {end_port}")
    print("Scan Started   :", datetime.now())
    print("-" * 65)

    # -------------------------
    #   MULTITHREADED SCAN
    # -------------------------

    # ThreadPoolExecutor manages worker threads efficiently
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        # Submit all port scan tasks to the thread pool
        future_to_port = {
            executor.submit(scan_port, target_ip, port): port
            for port in range(start_port, end_port + 1)
        }

        # Process results as soon as threads complete
        for future in as_completed(future_to_port):

            # Get the port number associated with this thread
            port = future_to_port[future]

            try:
                # Retrieve result from thread
                if future.result():
                    print(f"[+] Port {port:<5} OPEN")
                    open_ports.append(port)

            except Exception:
                # Catch and ignore unexpected thread-level errors
                pass

    # -------------------------
    #   SCAN COMPLETION
    # -------------------------

    print("-" * 65)
    print("Scan Completed :", datetime.now())

    # Display final scan results
    if open_ports:
        print("\nOpen Ports Found:")
        for port in sorted(open_ports):
            print(f" - Port {port}")
    else:
        print("\nNo open ports found.")

    # Ethical disclaimer
    print("\n⚠️  Ethical Reminder:")
    print("   Scan only systems you own or have explicit permission to test.")


# =========================
#     PROGRAM ENTRY POINT
# =========================

# Ensures main() runs only when this file is executed directly
if __name__ == "__main__":
    main()
