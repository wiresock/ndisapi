# UDP to TCP Converter

This C++ program acts as a UDP to TCP (and vice versa) converter, using Windows Packet Filter to intercept and modify network packets. 

## Running the Application

After building the project, you can run the application with the following command:

`./udp2tcp`

The application will prompt you to select a network interface and specify the server or client mode as well as the UDP port number.

## How it Works

The application uses the Windows Packet Filter (WinpkFilter) library to intercept network packets. The `load_filters` function sets up three filters:

1. Incoming TCP packets with a specific port are redirected and processed to convert TCP to UDP.
2. Outgoing UDP packets with a specific port are redirected and processed to convert UDP to TCP.
3. All other packets are passed without processing in user mode.

In the `main` function, the application creates a `simple_packet_filter` object with two lambda functions. The first lambda function handles incoming TCP packets and converts them to UDP. The second lambda function handles outgoing UDP packets and converts them to TCP.
