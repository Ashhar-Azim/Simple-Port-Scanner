"""
Multithreaded Port Scanner with Rate Limiting & File Output
-----------------------------------------------------------
Author  : Ashhar 
Purpose : Scan a target host responsibly using throttled multithreading
Ethics  : Scan only systems you own or have permission to test
"""

# =========================
#          IMPORTS
# =========================

import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================
#      PORT SCAN LOGIC
# =========================

def scan_port(target_ip, port, timeout=0.5):
    """
    Attempts to connect to a TCP port on the target system.

    Parameters:
        target_ip (str): Target IP address
        port (int): Port number
        timeout (float): Socket timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex returns 0 if connection succeeds
        result = sock.connect_ex((target_ip, port))

        sock.close()
        return result == 0

    except socket.error:
        return False


# =========================
#        MAIN PROGRAM
# =========================

def main():
    print("=" * 75)
    print("   Multithreaded Port Scanner (Rate Limited & Logged)")
    print("=" * 75)

    # -------------------------
    #        USER INPUT
    # -------------------------

    target = input("Enter target IP or hostname: ")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Invalid hostname.")
        return

    try:
        start_port = int(input("Enter start port: "))
        end_port   = int(input("Enter end port  : "))
    except ValueError:
        print("Error: Ports must be integers.")
        return

    # -------------------------
    #     SCAN CONFIGURATION
    # -------------------------

    MAX_THREADS       = 50     # Maximum concurrent threads
    PORTS_PER_BATCH   = 50     # Rate limit: ports scanned per batch
    BATCH_DELAY       = 1.0    # Throttle delay (seconds)
    SOCKET_TIMEOUT    = 0.5

    open_ports = []

    # Output file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"scan_results_{target_ip}_{timestamp}.txt"

    print("\nTarget IP       :", target_ip)
    print("Port Range     :", f"{start_port} - {end_port}")
    print("Threads Used   :", MAX_THREADS)
    print("Rate Limit     :", f"{PORTS_PER_BATCH} ports / batch")
    print("Throttle Delay :", f"{BATCH_DELAY} seconds")
    print("Scan Started   :", datetime.now())
    print("-" * 75)

    # -------------------------
    #     RATE-LIMITED SCAN
    # -------------------------

    with open(output_file, "w") as file:
        file.write(f"Port Scan Results for {target_ip}\n")
        file.write(f"Scan Time: {datetime.now()}\n")
        file.write("-" * 60 + "\n")

        # Process ports in controlled batches
        for batch_start in range(start_port, end_port + 1, PORTS_PER_BATCH):

            batch_end = min(batch_start + PORTS_PER_BATCH - 1, end_port)
            current_batch = range(batch_start, batch_end + 1)

            print(f"\nScanning ports {batch_start} to {batch_end}...")

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

                futures = {
                    executor.submit(scan_port, target_ip, port, SOCKET_TIMEOUT): port
                    for port in current_batch
                }

                for future in as_completed(futures):
                    port = futures[future]

                    try:
                        if future.result():
                            print(f"[+] Port {port:<5} OPEN")
                            open_ports.append(port)
                            file.write(f"OPEN  - Port {port}\n")
                    except Exception:
                        pass

            # Throttle scanning speed
            time.sleep(BATCH_DELAY)

        file.write("-" * 60 + "\n")
        file.write(f"Open Ports Count: {len(open_ports)}\n")

    # -------------------------
    #        FINAL OUTPUT
    # -------------------------

    print("\n" + "-" * 75)
    print("Scan Completed :", datetime.now())

    if open_ports:
        print("\nOpen Ports Found:")
        for port in sorted(open_ports):
            print(f" - Port {port}")
    else:
        print("\nNo open ports found.")

    print(f"\nResults saved to file: {output_file}")
    print("\n⚠️  Ethical Reminder: Authorized testing only.")


# =========================
#      ENTRY POINT
# =========================

if __name__ == "__main__":
    main()
