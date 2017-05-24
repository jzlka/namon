BP
===
[![Build Status](https://travis-ci.org/TheKuko/BP.svg?branch=master)](https://travis-ci.org/TheKuko/BP)
[![Build status](https://ci.appveyor.com/api/projects/status/3mxuyc2dmaml6dr0?svg=true)](https://ci.appveyor.com/project/TheKuko/bp)


Multiplatform C++ tool which captures network traffic into pcap-ng file and extends it with application tags. 
The application tag consists of recognized application and its socket records. The socket record uniquely identifies group of packets which belong to one applications socket.  
Application tags are appended to the end of the capture pcap-ng file as one Custom Block. Structure of the block is documented in *doc/xzuzel00_BP.pdf* (Chapter 6).

**Features**
- Works on Windows and Linux (FreeBSD and MacOS support will be added in the future)
- Uses **PCAPNG** so Wireshark can read the capture file as usual

The application was tested on the following platforms:
- Windows:
    - Windows 10 (Npcap)
    - Windows 7 (WinPcap)
- Linux:
    - Ubuntu (15.04 LTS, 16.04 LTS)
    - lubuntu (17.04)
    - Debian (8 Jessie)
    - Kali (2016.1, 2016.2)

Detailed class documentation can be found at https://thekuko.github.io/BP-doc/

**Dependencies**
- Windows: Npcap/WinPcap
- Linux: libpcap

## Build
**Linux**    

    $ git clone https://github.com/TheKuko/BP.git
    $ cd BP
    $ make

**Windows**
1. Clone https://github.com/TheKuko/BP.git
2. Download [npcap-sdk](https://nmap.org/npcap/) into _libs/_ folder, extract it and rename extracted folder to *npcap-sdk*
3. Build *win32/BP.sln* using Visual Studio

Final binary is located in _bin/_ folder.

**Makefile parameters**

    * make              - build the tool
    * make debug        - build the tool with debug info and without optimisations
    * make libs         - run helper script to download & install PF_RING/netmap/PFQ (interactive)(**TODO**)
    * make pf_ring      - build against PF_RING downloaded in libs/ folder
    * make netmap       - build against netmap downloaded in libs/ folder (**TODO**)
    * make pfq          - build against PFQ downloaded in libs/ folder (**TODO**)
    * make test         - run basic tests (**TODO**)
    * make pack         - create gzip file
    * make doxygen      - make doxygen documentation in doc/ folder
    * make clean        - clean compiled binary, archive file, object files and \*.dSYM files
    * make clean-tests  - clean compiled tests
    * make clean-doc    - delete generated documentation
    * make clean-all    - clean, clean-tests, clean-doc

## Run parameters
    ./tool [-v[<level>]] [-i <interface>] [-w <output_file>]
       -v/--verbosity      Verbosity level. Possible values are 0(NONE), 1(ERR), 2(WARNING), 3(INFO). If no value is specified, 1 is used.
       -i/--interface      Capturing interfec. If the tool is run without this parameter, available interfaces will be printed
       -w/--output-file    Name of the output file. Default filename is tool_capturedTraffic.pcapng
       -h/--help           Print help message.

## TODO
