# PcapPlusPlus Demo

This project leverages the [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) library to intercept network packets, specifically focusing on extracting the Server Name Indication (SNI) from HTTPS packets. The program also performs Transport Layer Security (TLS) fingerprinting to identify the specific version of TLS being utilized.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- The `Windows Packet Filter` driver must be loaded on your system to use this application.
- This project depends on the PcapPlusPlus library. You will need to install this library and its static triplets using [vcpkg](https://github.com/microsoft/vcpkg), a C++ library manager.

For a 32-bit Windows system, you can install the necessary triplet with the following command:

```bash
vcpkg install pcapplusplus --triplet x86-windows-static
```

For a 64-bit Windows system, use the following command instead:

```bash
vcpkg install pcapplusplus --triplet x64-windows-static
```

### Running the Project

After you've installed the PcapPlusPlus library, you can now build and run the project to start intercepting network packets and extracting SNI information from HTTPS packets.

## Features

- Network Packet Interception: The application captures and analyzes network packets in real-time.
- SNI Extraction: It can extract the Server Name Indication (SNI) from HTTPS packets.
- TLS Fingerprinting: The application can also identify the specific version of Transport Layer Security (TLS) being used.



