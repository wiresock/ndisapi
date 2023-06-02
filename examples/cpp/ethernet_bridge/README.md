# EthernetBridge

The EthernetBridge example is a simple C++ program that implements an Ethernet bridge. An Ethernet bridge is a network device that connects two or more Ethernet networks together by forwarding frames between the networks based on their MAC addresses.

## Code Overview

init() - This function initializes the bridge. It performs the following operations:

1. Opens the network interfaces.
2. Creates a list of MAC addresses for each network interface.
3. Creates a table of MAC addresses to network interfaces.

run() - This function is the main loop of the bridge. It continuously receives frames from the network interfaces and forwards them to the appropriate network. It performs the following operations:

1. Receives a frame from a network interface.
2. Looks up the destination MAC address in the table of MAC addresses to network interfaces.
3. If the destination MAC address is found, forwards the frame to the network interface associated with the destination MAC address.
4. If the destination MAC address is not found, drops the frame.

## Acknowledgments

- The code uses the NDISAPI to open and manage network interfaces.
- The code uses a table of MAC addresses to network interfaces to keep track of which network interface is associated with each MAC address.
- The code uses a loop to continuously receive frames from the network interfaces and forward them to the appropriate network.
- The code drops frames that do not have a destination MAC address.

## More information
Please read this [blog post](https://www.ntkernel.com/bridging-networks-with-windows-packet-filter/)



