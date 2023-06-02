# Capture Packet Filter

## Overview

This project is an example of how to intercept network packets, write packet data into a file, and pass them on, facilitating packet analysis and troubleshooting. The `Windows Packet Filter` driver must be loaded for the program to run.

## Code Description

The main function of this program initiates a unique pointer to a `ndisapi::fastio_packet_filter` object. This object has two main lambda functions:

1. The first lambda function is triggered for each incoming packet. It writes the packet data to a file and then passes the packet back to the filter.
2. The second lambda function is triggered for each outgoing packet. It writes the packet data to the file and then passes the packet back to the filter.

After initialization, the program checks whether the `Windows Packet Filter` driver is loaded. If not, the program exits. If the driver is loaded, the program displays a list of available network interfaces and prompts the user to select an interface for filtering.

The user is then prompted to enter a filename where the packet capture will be saved. If the file opens successfully, the program begins filtering traffic on the selected interface. The user can stop filtering at any time by pressing any key.

## Usage

Compile and run the program. Follow the prompts to choose a network interface and specify a filename for the capture. Press any key to stop filtering.

