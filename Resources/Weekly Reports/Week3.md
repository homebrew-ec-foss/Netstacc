# Week 3 Progress

## Aishwarya's progress
- Extended the classifier's UDP handler.
- Added header parsing (udp.h/udp.c) and pseudo-header checksum verification, reusing the existing compute_checksum() utility.
- Tested with ncat -u and cross-verified against Wireshark.
- Fixed a byte-order bug (htons() on the pseudo-header length). PR opened, scoped to just the UDP files.
## Next week:
- Read through RFC 7414 and RFC 9293
- Read about packetization and TCP handshake and implementing them.
- TCP state machine implementation

## Visruth's Progress
- Read through half of RFC 793
- Understood how packetization works 
- Understood TCP handshake

### Next Week
- Reading RFC 7414
- Implement TCP handshake
- Implement packetization


