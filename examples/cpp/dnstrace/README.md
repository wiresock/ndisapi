# DNS Tracer

`dnstrace` is a console application written in C++. It provides a detailed trace of DNS (Domain Name System) responses by parsing the DNS packet structure. This can be useful for network debugging, security monitoring, and research purposes.This sample also demonstares how to link NDISAPI statically and dynamically (using corresponding congigurations).

## Features

- Parses and prints out key elements from IP, UDP, and DNS headers.
- Extracts and displays DNS response data, including record types like A, NS, CNAME, SOA, WKS, PTR, MX, AAA, SRV and ANY.
- Uses `Windows Packet Filter` to filter the network traffic.
- Allows the user to select a network interface to filter.
- Handles IPv4 and IPv6 addresses.
  
## How it works

The application captures packets coming from the DNS server (port 53) using `Windows Packet Filter`. It then parses these packets, extracting the IP, UDP, and DNS headers. For each DNS response, it extracts and prints out the DNS record type and data. The application continues to run until the user interrupts it.

## Prerequisites

- The `Windows Packet Filter` driver must be loaded on your system to use this application.

## Usage

Run the application from the command line with:

```bash
./dnstrace
```

If the `Windows Packet Filter` driver is loaded, the application will print a list of available network interfaces. Select the interface you want to filter by entering its number. The application will start capturing and parsing DNS responses on that interface.




