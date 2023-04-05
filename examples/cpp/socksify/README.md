# Windows Packet Filter Socksify Example

This example demonstrates how to use the Windows Packet Filter to redirect the selected local process through a specified SOCKS5 proxy. In this case, we will redirect Firefox browser traffic through an SSH tunnel.

## Prerequisites

* Local SOCKS5 proxy (e.g., using an SSH command such as `ssh user@domain.com -D 8080`)

## Usage

1. Start your local SOCKS5 proxy. For example, using an SSH command:

```
ssh user@domain.com -D 8080
```

This command will expose a SOCKS5 proxy on localhost 127.0.0.1:8080.

2. Run the socksify.exe tool and follow the prompts:

```
D:\projects\winpkfilter\ndisapi\tools_bin_x64\tools\amd64>socksify.exe
WinpkFilter is loaded

Available network interfaces:

<numbered list of available network interfaces>

Select interface to filter: <interface number>

Application name to socksify: <application name>

SOCKS5 proxy IP address: <proxy IP address>

SOCKS5 proxy port: <proxy port>

Local port for the transparent TCP proxy server: <local port>

SOCKS5 USERNAME[optional]: <username>

SOCKS5 PASSWORD[optional]: <password>
```

Example:

```
Select interface to filter: 12

Application name to socksify: firefox

SOCKS5 proxy IP address: 127.0.0.1

SOCKS5 proxy port: 8080

Local port for the transparent TCP proxy server: 9000

SOCKS5 USERNAME[optional]:

SOCKS5 PASSWORD[optional]:
No suitable username or password specified, using anonymous authentication with SOCKS5 proxy
Press any key to stop filtering
Redirect entry was found for the port 50946 is 13.32.110.25:443
Redirect entry was found for the port 50948 is 34.160.90.233:443
Redirect entry was found for the port 50949 is 34.160.90.233:443
Redirect entry was found for the port 50950 is 34.160.90.233:443
...
```
After completing these steps, all traffic from the specified application (in this case, the Firefox browser) will be redirected through the transparent local proxy running on the specified local port (e.g., 9000), and then through the SOCKS5 proxy exposed by the SSH command at 127.0.0.1:8080.
