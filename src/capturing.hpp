/** 
 *  @file       capturing.hpp
 *  @brief      Network traffic capture header file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:48
 *  Edited:     20.03.2017 15:10
 *  Version:    1.0.0
 */

#pragma once

#include <iostream>         //  exception, string
#include <fstream>          //  fstream
#include <sys/types.h>      //  u_char
#include "netflow.hpp"

#if defined(__APPLE__) || defined(__linux__)
#include <netinet/ip.h>         //  ip
#include <netinet/ip6.h>        //  ip6_hdr
#endif


//! Size of a libpcap error buffer
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif



/*!
 * @brief       Starts network traffic capture
 * @param[in]   oFilename   Output file name
 * @return      Result of the capturing
 */
int startCapture(const char *oFilename);
/*!
 * @brief       Function that processes every packet
 * @param[in]   args    Array with pointer to RingBuffer and Cache
 * @param[in]   header  Libpcap header
 * @param[in]   bytes   Captured packet
 */
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *bytes);
/*!
 * @brief       Parses IP header
 * @param[out]  n           Netflow which will be filled with parsed information
 * @param[out]  ip_size     Size of the IP header
 * @param[in]   ip_hdr      Pointer to the IP header
 * @param[in]   ether_type  Ethernet frame type
 * @return      IP headers validity
 */
inline int parseIp(Netflow &n, unsigned int &ip_size, void * const ip_hdr, const unsigned short ether_type);
/*!
 * @brief       Parses layer 4 header
 * @param[out]  n   Netflow which will be filled with parsed information
 * @param[in]   hdr Header pointer
 * @return      Layer 4 headers validity
 */
inline int parsePorts(Netflow &n, void *hdr);
/*!
 * @return  True if an application should stop
 */
bool stop();
/*!
 * @brief       Signal handler function
 * @param[in]   signum  Received interrupt signal
 */
void signalHandler(int signum);



/*!
 * @class   pcap_ex
 * @brief   Exception used during pcap related errors
 */
struct pcap_ex: public std::exception
{
    std::string msg;
public:
    pcap_ex(const std::string &m, const char *errbuf): msg(m + "\nlibpcap: " + errbuf) {}
    const char *what() const throw() 
        { return msg.c_str(); }
};
