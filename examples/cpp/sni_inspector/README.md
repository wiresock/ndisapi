# SNI Inspector

The `sni_inspector` is a C++ program that inspects the Server Name Indication (SNI) extension of TLS/SSL connections and Host from HTTP packets. This program utilizes the Windows Packet Filter driver to intercept and analyze network traffic.

## Overview

This program follows these steps:

1. It checks if the WinpkFilter driver is loaded.
2. If the driver is loaded, it displays a list of available network interfaces.
3. The user can select an interface to filter.
4. It starts filtering traffic on the selected interface and writes the hostnames from the SNI extension of each TLS/SSL connection and Host from HTTP packets to the console.
5. The program continues filtering until the user presses a key.

This tool can be valuable for troubleshooting TLS/SSL connection issues or for monitoring server traffic.

## Prerequisites

The program depends on the the Windows Packet Filter (WinpkFilter) driver. Ensure you have the WinpkFilter driver installed and loaded on your system.
