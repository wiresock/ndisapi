# pcapplusplus

This code utilizes the PcapPlusPlus library to intercept network packets and extract the Server Name Indication (SNI) from HTTPS packets. Additionally, it performs Transport Layer Security (TLS) fingerprinting to identify the specific version of TLS being used.

To use this code, you will need to install the PcapPlusPlus library and its static triplets using vcpkg. You can install the necessary triplet for a 32-bit Windows system with the following command:

`vcpkg install pcapplusplus --triplet x86-windows-static`

If you are using a 64-bit Windows system, you can use the following command instead:

`vcpkg install pcapplusplus --triplet x64-windows-static`

After installing the library, you can run the code to intercept network packets and extract SNI information from HTTPS packets.



