BP
===
[![Build Status](https://travis-ci.org/TheKuko/BP.svg?branch=master)](https://travis-ci.org/TheKuko/BP)

Multiplatform C++ tool which captures network traffic into pcap-ng file and extends it with application tags. The application tag consists of recognized application and its socket records. The socket record uniquely identifies group of packets which belongs to the application and one socket. It consists of local IP address (preceded with its version), local port, transport-layer protocol and time (in miliseconds from the epoch) of the first and the last packet in the group

**Features**
- Works on Windows and Linux
- Uses **PCAPNG** so Wireshark can read the capture file as usual

The application was tested on the following platforms:
**Debian 8 Jessie**, **lubuntu 17.04**, **Ubuntu 16.04**, **Ubuntu 17.04**, **Kali 
- Windows:
    - Windows 10, x64 (Npcap)
    - Windows 7, x64 (WinPcap)
- Linux:
    - Ubuntu (15.04 LTS, 16.04 LTS)
    - lubuntu (17.04)
    - Kali 2016.1

Other operating systems will be implemented in the future.
Detailed class documentation can be found at https://thekuko.github.io/BP-doc/

**Dependencies**
- Windows: Npcap/WinPcap
- Linux: libpcap

**Installation**
    
    git clone https://github.com/TheKuko/BP.git
    cd BP/tool
    make

More information:
    bin/tool --help
    make help

## TODO
* README.md
