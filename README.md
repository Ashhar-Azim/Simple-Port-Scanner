# Simple-Port-Scanner (Python)
Scan a target IP for open ports (like a tiny Nmap).

## Overview
This project is a beginner-level cybersecurity tool that scans a target host
to identify open TCP ports. It demonstrates basic concepts of networking,
reconnaissance, and ethical security testing.

⚠️ This tool is for educational purposes only.
Scan only systems you own or have permission to test.

## Features
- Scans a user-defined port range
- Identifies open TCP ports
- Displays scan results clearly
- Simple and readable Python code

## Technologies Used
- Python 3
- socket library
- datetime module

## How It Works
1. User enters target IP or hostname
2. User specifies port range
3. Script attempts TCP connections
4. Open ports are reported

## Usage
```bash
python port_scanner.py
```

____________________
🔧 Next smart upgrades (in order)

Add multithreading (huge performance boost)

Add service name detection

Save results to a file

Add CLI arguments (argparse)
___________________

