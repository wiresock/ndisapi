# IPv6 Parser

This project demonstrates the useage of `ipv6_parser` class for parsing IPv6 headers and finding the transport payload.

## Main Functionality

The `ipv6_parser::find_transport_header` function is used to parse IP headers until the transport payload. It takes a pointer to the IP header and the size of the IP packet in octets as inputs, and returns a pointer to the IP packet payload (TCP, UDP, ICMPv6, etc.) and protocol.

The `main` function uses `ndisapi::fastio_packet_filter` to intercept IPv6 packets. It then uses the `find_transport_header` function to parse the IP headers, and if the protocol is TCP, it performs process lookups.

## Dependencies

- You must have `Windows Packet Filter` installed on your machine to build and run this project. 



