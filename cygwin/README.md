# NDISAPI Library for Cygwin

This directory contains the Makefile and instructions to build the Cygwin variant of the NDISAPI static library and basic example applications.

## Prerequisites

- Cygwin environment with `g++` and standard build tools installed.
- Source files for the `ndisapi` library and examples.

## Building the Library

1. Open your Cygwin terminal.
2. Navigate to the `cygwin` directory within the `ndisapi` library repository.
3. Run `make` to build the static library and all basic examples.

   ```bash
   make
   ```

This will compile the `ndisapi` static library and the following example applications:

- `listadapters`
- `packthru`
- `filter`
- `filterstats`
- `gertunnel`
- `ndisrequest`
- `packetsniffer`
- `passthru`
- `wwwcensor`

## Cleaning Build Artifacts

To clean up all build artifacts, run:

```bash
make clean
```

## Example Usage

After building, you can run the example applications directly from the `bin` directory. For instance, to run `listadapters`:

```bash
./bin/x64/Release/listadapters
```

(Adjust the path based on your build architecture and configuration.)

## Demo Output

Here are brief examples of the output you can expect from running the `listadapters` and `packthru` samples:

### listadapters

```bash
$ ./bin/x64/Release/listadapters
The following network interfaces are available to MSTCP:
1) Ethernet.
        Internal Name:   \DEVICE\{...}
        Current MAC:     B04F13FB9614
        ...
2) Local Area Connection* 2.
        Internal Name:   \DEVICE\{...}
        Current MAC:     3E219C3EC44D
        ...
... (additional interfaces listed here) ...
```

### packthru

```bash
$ ./bin/x64/Release/packthru 4 5
1 packet received from the driver

4 - Interface --> MSTCP
        Packet size = 42
        Source MAC:              50FF20902F15
        Destination MAC:         FFFFFFFFFFFF
        ... (packet details) ...
Sending 1 packets to protocols
... (additional packet details) ...
Filtering complete
```

These outputs are just excerpts to demonstrate the format. When you run these samples in your environment, you'll see detailed information specific to your network interfaces and traffic.

## Notes

- The provided Makefile is configured for the Cygwin environment. For other environments, modifications may be necessary.
