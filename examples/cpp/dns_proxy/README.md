# DNS Proxy Server

## Overview

This is a basic DNS Proxy Server application implemented in C++. It allows you to intercept and redirect all DNS packets to a specified DNS server. This is useful for network monitoring, debugging, and other networking tasks.

## Code Description

The `main()` function of the program begins by prompting the user to input the IP address of the DNS server where the DNS requests will be forwarded.

The application then creates an instance of `ndisapi::udp_proxy_server` which is designed to handle the redirection of UDP traffic. The main logic of redirection is encapsulated in a lambda function passed to the `ndisapi::udp_proxy_server` constructor. This function checks whether the remote port is 53 (the standard DNS port). If it is, it redirects the request to the specified DNS server. If not, it simply returns without any redirection.

The application also sets up a logging function, `log_printer`, to display messages about the status of the application. This function is thread-safe.

Finally, the application starts the proxy server and waits for the user to press any key to stop the filtering process.

If any exception occurs during the execution, it is caught and displayed in the console.

## Usage

Compile and run the program. You will be prompted to enter the IP address of the DNS server where the DNS requests should be forwarded. Press any key to stop filtering.
