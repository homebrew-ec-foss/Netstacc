# Netstacc
_A DIY TCP/IP Stack built from scratch in C!_

Currently supports parsing IPv4, replying to ICMP Echo Requests (Ping), verifying UDP checksums, and tracking dropped packets, all visualized through an advanced, live terminal dashboard.

## Setup Instructions

1. **Configure the virtual network interface (TUN):**
   This sets up `tun0` and assigns it the IP address `10.0.0.1`.
   ```bash
   make setup

    Compile and run the stack:
    Bash

    make clean
    make
    make run

    Note: The stack must remain running in this terminal to process packets and render the UI.

How to Test the Stack

Once Netstacc is running, open a second terminal window to send traffic to your custom stack.
Testing ICMP (Ping)

Send a standard ping to the TUN interface. Netstacc will catch the request, swap the source/destination IPs, recalculate the checksum, and transmit a reply.
Bash

ping 10.0.0.1

Watch the Netstacc dashboard update the RX/TX packet counts and bytes in real-time.
Testing UDP

Send raw UDP text data to the stack using ncat or nc (Netcat).
Bash

ncat -u 10.0.0.1 8080

Type any message and hit Enter. The dashboard will catch the payload, extract the ports, verify the UDP pseudo-header checksum, and flag any malformed packets.
