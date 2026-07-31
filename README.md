# Netstacc

A custom TCP/IP network stack built from scratch in C. 

Netstacc processes raw packets through a virtual TUN interface, parses IPv4 headers, handles ICMP echo requests, validates UDP pseudo-header checksums, and tracks packet drops in real time via a live terminal dashboard.

---

## Features

* **IPv4 Parsing:** Ingests raw frames and routes traffic based on protocol headers.
* **ICMP Handling:** Responds to ICMP Echo Requests and tracks transmission metrics.
* **UDP Processing:** Parses source and destination ports, calculates pseudo-header checksums, and extracts raw text payloads.
* **Terminal Dashboard:** Displays live packet counts, byte totals, and drop diagnostics in a clean interface.

---

## Setup Instructions

1. Configure the virtual network interface (`tun0`):
   ```bash
   sudo ip link set dev tun0 up
   sudo ip addr add 10.0.0.1/24 dev tun0
   ```

2. Compile and run the stack:
   ```bash
   make clean
   make
   make run
   ```
   *Note: The terminal running `make run` must stay open to process packets and render the live UI.*

---

## Testing the Stack

Open a second terminal window to send test traffic through the virtual tunnel.

### 1. Testing ICMP (Ping)

Send a standard ping to the tunnel subnet:
```bash
ping 10.0.0.2
```
The stack will capture the request, verify the header, transmit a reply, and update the live dashboard counters.

### 2. Testing UDP Payloads

Send raw text data to the stack using Netcat:
```bash
nc -u 10.0.0.2 53
```
Type any message and press Enter. The console will display the source port, destination port, packet length, checksum status, and the extracted text payload.
