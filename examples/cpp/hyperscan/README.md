# Hyperscan: Network Packet Analysis Example

## Overview

`Hyperscan` is a high-performance example application showcasing the integration of the [Hyperscan](https://github.com/intel/hyperscan) and [llhttp](https://github.com/nodejs/llhttp) libraries. This application intercepts network packets, parses them, detects HTTP protocol sessions, and applies the HTTP protocol parsing on the detected sessions using `llhttp`.

This practical application can significantly contribute to network security and monitoring efforts, enabling the identification and in-depth analysis of HTTP traffic within a network. 

## Key Features

- High-performance network packet interception
- HTTP protocol session detection
- In-depth HTTP protocol parsing for detected sessions
- Utilization of Hyperscan and llhttp libraries

## Limitations

Please note that this example application is not engineered to handle TCP packet retransmissions or reordering. Therefore, it might not perform optimally on unreliable connections. It is specifically designed and optimized for high-quality, reliable connections.

## Installation

### Prerequisites

Ensure you have the following installed on your system:

- Hyperscan 5.2 or later (including headers and libraries)
- llhttp headers and libraries

### Installation Steps

You can use `vcpkg` to install the required Hyperscan and llhttp libraries:

Install Hyperscan:

```bash
vcpkg install hyperscan:x86-windows-static hyperscan:x64-windows-static
```

Install llhttp:

```bash
vcpkg install llhttp:x86-windows-static llhttp:x64-windows-static
```

With these libraries installed, you're ready to compile and run the hyperscan application.
