# Windows Packet Filter Rebind Example

This is an example application that demonstrates how to use the [Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/) driver to rebind outgoing TCP/UDP connections for the specified application from the default network interface to a different one. 

## Description
For example, we have a host on our home network connected to LAN (192.168.100.25/24) and Wi-Fi (192.168.100.165/24) at the same time. By default, Windows will use the LAN interface (192.168.100.25) to connect to the Internet, the Wi-Fi interface will be idle. Rebind allows you to redirect TCP/UDP connections for a selected application (e.g. Firefox) over Wi-Fi (instead of LAN) while other applications continue to use the LAN.

## Prerequisites

- Windows 10 (or Windows Server 2019)
- Visual Studio 2022
- Windows Packet Filter driver (download [here](https://www.ntkernel.com/windows-packet-filter/))

## How to Run

1. Download and install the Windows Packet Filter driver.
2. Open the `ndisapi.sln` solution in Visual Studio 2022.
3. Build the `rebind` project.
4. Run the `rebind.exe` application.

## Usage

The `rebind.exe` application performs network interface rebinding for a specified application running on a Windows computer. The following steps outline how to use this example:

1. Upon starting the application, the user is presented with a list of available network interfaces that are connected to the Internet. The user can select the default interface or any of the other available interfaces to perform the rebinding operation.

2. The user is then prompted to enter the name of the application to rebind. The application name can be obtained from the Task Manager.

3. Once the user has selected the interface and entered the application name, the application performs the rebinding operation and prints the new configuration parameters, including the source and destination MAC and IP addresses.

4. The user can stop the filtering operation at any time by pressing any key.

## Example Output

Rebinding chrome.exe from the default (Ethernet) network interface to the Wi-Fi interface:

```
WinpkFilter is loaded

Default Internet connected network interface:
    Ethernet	:	Intel(R) Ethernet Connection I219-LM
            10.0.0.9/8
            fdcf:7044:4b4d:3210:1875:8cd8:e40f:d31c/64
            00:1f:16:83:1a:9e
Alternative Internet connected network interfaces:
    1. Wi-Fi	:	Microsoft Wi-Fi Direct Virtual Adapter #2
            192.168.3.3/24
            fe80::d56a:fcf6:8206:f42c/64
            fa:71:3e:3b:21:e6
Application name to rebind: chrome

Select network interface to rebind: 1

Rebind parameters:

Application name: chrome
Rebind adapter source MAC: 00:1f:16:83:1a:9e
Default adapter source MAC: 00:1f:16:83:1a:9e
Rebind adapter gateway MAC: 38:60:77:85:18:22
Rebind adapter source IP address: 192.168.3.3
Default adapter source IP address: 10.0.0.9

Press any key to stop filtering
Exiting...
```

Rebinding chrome.exe from the default (WireGuard) network interface to the Wi-Fi interface. In this demo chrome.exe bypasses WireGuard tunnel:

```
WinpkFilter is loaded

Default Internet connected network interface:

        {C6EC8509-53E3-2F0E-EE73-4932DCF82ED8}  :       WireGuard Tunnel #2
                fd42:42:42::3
                10.66.66.3
        Gateway:

Alternative Internet connected network interfaces:

1.      {05F9267C-C548-4822-8535-9A57F1A99DB7}  :       Hyper-V Virtual Ethernet Adapter #2
                fd42:42:42::5
                fe80::2e91:54ce:3a6:2823
                172.16.3.229
        Gateway:
                fd42:42:42::1 : 000000000000
                172.16.0.1 : 64D154C25BEE

Application name to rebind: chrome

Rebind parameters:

Application name: chrome
Rebind adapter source MAC: 18473D60269D
Default adapter source MAC: 000000000000
Rebind adapter gateway MAC: 64D154C25BEE
Rebind adapter source IP address: 172.16.3.229
Default adapter source IP address: 10.66.66.3


Press any key to stop filtering
Exiting...
```

## License

This example is licensed under the MIT License.
