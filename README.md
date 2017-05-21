BP
===
[![Build Status](https://travis-ci.org/TheKuko/BP.svg?branch=master)](https://travis-ci.org/TheKuko/BP)
#https://ci.appveyor.com/project/TheKuko/bp

Multiplatform C++ tool which captures network traffic into pcap-ng file and extends it with application tags. 
The application tag consists of recognized application and its socket records. The socket record uniquely identifies group of packets which belongs to one applications socket. It consists of local IP address (preceded with its version), local port, transport-layer protocol and time (in microseconds of Unix time) of the first and the last packet in the group. 
Application tags are appended to the end of the capture pcap-ng file in Custom Block. Structure of the block is documented in doc/xzuzel00_BP.pdf (Chapter 6).

**Features**
- Works on Windows and Linux (FreeBSD and MacOS in the future)
- Uses **PCAPNG** so Wireshark can read the capture file as usual

The application was tested on the following platforms:
- Windows:
    - Windows 10, x64 (Npcap)
    - Windows 7, x64 (WinPcap)
- Linux:
    - Ubuntu (15.04 LTS, 16.04 LTS)
    - lubuntu (17.04)
    - Debian (8 Jessie)
    - Kali 2016.1, 2016.2

Detailed class documentation can be found at https://thekuko.github.io/BP-doc/

**Dependencies**
- Windows: Npcap/WinPcap
- Linux: libpcap

## Installation
On Windows, **npcap-sdk** must be located in libs/ folder
    
    git clone https://github.com/TheKuko/BP.git
    cd BP
    make

**Makefile parameters**

    * make              - build the tool
    * make debug        - build the tool with debug info and without optimisations
    * make libs         - run helper script to download & install PF_RING/netmap/PFQ (interactive)(**TODO**)
    * make pf_ring      - build against *PF_RING* downloaded in libs/ folder
    * make netmap       - build against *netmap* downloaded in libs/ folder (**TODO**)
    * make pfq          - build against *PFQ* downloaded in libs/ folder (**TODO**)
    * make test         - run basic tests (**TODO**)
    * make pack         - create gzip file
    * make doxygen      - make doxygen documentation in doc/ folder
    * make clean        - clean compiled binary, archive file, object files and \*.dSYM files
    * make clean-tests  - clean compiled tests
    * make clean-doc    - delete generated documentation
    * make clean-all    - clean, clean-tests, clean-doc

## Run parameters
    ./tool [-v[<level>]] [-i <interface>] [-w <output_file>]
    * **-v**/--verbosity      Verbosity level. Possible values are 0(NONE), 1(ERR), 2(WARNING), 3(INFO). If no value is specified, 1 is used.
    * **-i**/--interface      Capturing interfec. If the tool is run without this parameter, available interfaces will be printed
    * **-w**/--output-file    Name of the output file. Default filename is tool_capturedTraffic.pcapng
    * **-h**/--help           Print help message.

## TODO
