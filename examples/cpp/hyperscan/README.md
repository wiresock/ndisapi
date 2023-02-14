# hyperscan

## Description

`hyperscan` is an example application that demonstrates how to utilize the [Hyperscan](https://github.com/intel/hyperscan) library and [llhttp](https://github.com/nodejs/llhttp) to parse intercepted network packets and detect HTTP protocol sessions. Once a session is detected, `llhttp` is used to parse the HTTP protocol of the session.

This example application can be useful for network security and monitoring purposes, where it can help to identify and analyze HTTP traffic within a network. 

## Installation

### Prerequisites

- Hyperscan 5.2 or later (including headers and libraries)
- llhttp headers and libraries