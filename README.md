Network Traffic Capturing With Application Tags
===
[![Build Status](https://travis-ci.org/TheKuko/namon.svg?branch=master)](https://travis-ci.org/TheKuko/namon)
[![Build status](https://ci.appveyor.com/api/projects/status/gow7petki0obew78?svg=true)](https://ci.appveyor.com/project/TheKuko/namon)


Multiplatform C++ tool which captures network traffic into pcap-ng file and extends it with application tags. 
The application tag consists of recognized application and its socket records. The socket record uniquely identifies group of packets which belong to one applications socket.  
Application tags are appended to the end of the capture pcap-ng file as one Custom Block. Structure of the block is documented in *[thesis.pdf](https://thekuko.github.io/BP/docs/thesis.pdf)* (Chapter 6).

### Features ###
- Works on Windows and Linux (FreeBSD and MacOS support will be added in the future)
- Uses **PCAPNG** so Wireshark can read the capture file as usual

### Dependencies ###
- Windows: Npcap/WinPcap
- Linux: libpcap

The application was tested on the following platforms:
- Windows:
    - Windows 10 (Npcap)
    - Windows 7 (WinPcap)
- Linux:
    - Ubuntu (15.04 LTS, 16.04 LTS)
    - lubuntu (17.04)
    - Debian (8 Jessie)
    - Kali (2016.1, 2016.2)

## Build
**Linux**    
```bash
git clone https://github.com/TheKuko/namon.git
cd namon
make
```

**Windows**
1. Clone https://github.com/TheKuko/namon.git
2. Download [npcap-sdk](https://nmap.org/npcap/) into _libs/_ folder, extract it and rename extracted folder to *npcap-sdk*
3. Build *win32/namon.sln* using Visual Studio

Final binary is located in **_bin/_** folder.

### Makefile parameters

    * make              - build the tool
    * make debug        - build the tool with debug info and without optimisations
    * make test         - run basic tests (**TODO**)
    * make pack         - create gzip file
    * make doxygen      - make doxygen documentation in doc/ folder
    * make clean        - clean compiled binary, archive file, object files and \*.dSYM files
    * make clean-tests  - clean compiled tests
    * make clean-doc    - delete generated documentation

[//]: <> (This is also a comment.)
[//]: # (This is also a comment.)
[//]: # (* This is also a comment.)
[//]: # (    * make clean-all    - clean, clean-tests, clean-doc)
[//]: # (    * make libs         - run helper script to download & install PF_RING/netmap/PFQ (interactive)(**TODO**))
[//]: # (    * make pf_ring      - build against PF_RING downloaded in libs/ folder)
[//]: # (    * make netmap       - build against netmap downloaded in libs/ folder (**TODO**))
[//]: # (    * make pfq          - build against PFQ downloaded in libs/ folder (**TODO**))

## Program arguments
```bash
namon [-v[<level>]] [-i <interface>] [-w <output_file>]
```

|Argument                                |Description                                                                                                                    |
|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
|`-h`, `--help`                          |Show help message and exit.                                                                                                    |
|`-v`, `--verbosity`                     |Select verbosity level 0(_disabled_), 1(_error_), 2(_warning_), 3(_info_). If no value is specified `1` is used by default.    |
|`-i <interface>`, `--interface`         |Capturing interface. If the tool is run without this parameter, available interfaces will be printed.                          |
|`-w <output_file>`, `--output-file`     |Name of the output file. Default filename is `namon_capturedTraffic.pcapng`.                                                    |

## Author
Jozef Zuzelka <jozef.zuzelka@gmail.com>

## More information

* [Doxygen documentation](https://thekuko.github.io/BP/docs/html/index.xhtml)
* ZUZELKA, Jozef. *Network traffc capturing with application tags*. Brno, 2017. Bachelor’s thesis. Brno University of Technology, Faculty of Information Technology. Supervisor Ing. Jan Pluskal ([thesis.pdf](https://thekuko.github.io/BP/docs/thesis.pdf))
* ZUZELKA, Jozef. _Network Traffc Capture with Application Tags_: Excel@FIT Conference (April 2017, Brno) ([paper](https://thekuko.github.io/BP/docs/clanek.pdf), [poster](https://thekuko.github.io/BP/docs/poster.pdf))
