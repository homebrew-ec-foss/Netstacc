# Week 2 Progress

## Aishwarya's Progress
- Implemented checksum calculation/verification, and protocol classification.
- Worked with TUN devices to capture and process IPv4 packets and went through IPv4 header parsing.
- Explored ICMP packet parsing and  the underlying packet processing concepts.

### Next Week
- Implement a UDP parser and generate UDP responses.
- Build a dashboard to display transmitted and received UDP and ICMP packet statistics.

## Visruth's Progress
- Implemented ICMP parsing and ICMP reply
- Read through how IP header parsing works.
- read the algorithm for checksum verification

### Next Week
- Desinging and implementing dashboard.
- Implement TCP, handle connections
- try to implement HTTP/1.1.

## Vansh's Progress
- Set up the TUN device interface to pull raw network packets directly from the Linux kernel.
- Wrote the main packet capture loop to continuously read raw bytes from the interface.
- Created the memory structures for IPv4 and ICMP headers to easily parse the incoming data.
- Added a bitwise filter to automatically drop IPv6 and other non-IPv4 traffic.

### Next Week
- Implement UDP parsing and get a basic UDP round-trip working.
- Set up a live packet counter that prints stats directly to the terminal.
