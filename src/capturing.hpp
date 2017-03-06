/** 
 *  @file       capturing.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:48
 *  Edited:     06.03.2017 17:45
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 */

#pragma once

#include <iostream>         //  exception, string
#include <fstream>          //  fstream
#include <sys/types.h>      //  u_char
#if defined(__APPLE__) || defined(__linux__)
#include <netinet/ip.h>         //  ip
#include <netinet/ip6.h>        //  ip6_hdr
//#include <netinet/in.h>
//#include <arpa/inet.h>
#endif
#include "netflow.hpp"


#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif




int startCapture(const char *oFilename);
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *bytes);
inline int parseIp(Netflow &n, unsigned int &ip_size, void * const ip_hdr, const unsigned short ether_type);
inline int parsePorts(Netflow &n, void *hdr);



struct pcap_ex: public std::exception
{
    std::string msg;
public:
    pcap_ex(const std::string &m, const char *errbuf): msg(m + "\nlibpcap: " + errbuf) {}
    const char *what() const throw() 
        { return msg.c_str(); }
};
