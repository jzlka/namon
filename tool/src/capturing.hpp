/** 
 *  @file       capturing.hpp
 *  @brief      Network traffic capture header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:48
 *   - Edited:  29.03.2017 19:58
 */

#pragma once

#include <iostream>             //  exception, string
#include <fstream>              //  fstream
#include <sys/types.h>          //  u_char
#include <vector>               //  vector
#include <atomic>               //  atomic

#if defined(__APPLE__) || defined(__linux__)
#include <netinet/ip.h>         //  ip
#include <netinet/ip6.h>        //  ip6_hdr
#endif

#include "debug.hpp"            //  log()


//! Size of a libpcap error buffer
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

class Netflow;
class TEntry;
class EnhancedPacketBlock;
template <class T>
class RingBuffer;
extern std::atomic<int> shouldStop;
extern std::vector<in_addr*> g_devIps;

/*!
 * An enum representing packet flow direction
 */
enum class Directions { 
    OUTBOUND, //!< Outgoing packets
    INBOUND,  //!< Incoming packets
    UNKNOWN,  //!< Direction is not known
};

/*!
 * @struct  PacketHandlerPointers
 * @brief   Struct used to pass packetHandler more pointers in one argument
 */
struct PacketHandlerPointers
{
    PacketHandlerPointers(RingBuffer<EnhancedPacketBlock> *fb, RingBuffer<Netflow> *cb) 
        : fileBuffer(fb), cacheBuffer(cb) {}
    RingBuffer<EnhancedPacketBlock> *fileBuffer = nullptr; //!< Pointer to RingBuffer which will be written to a file
    RingBuffer<Netflow> *cacheBuffer = nullptr;            //!< Used cache
};



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
 * @param[in]   dir         Packet direction
 * @param[in]   ip_hdr      Pointer to the IP header
 * @param[in]   ether_type  Ethernet frame type
 * @return      IP headers validity
 */
inline int parseIp(Netflow &n, unsigned int &ip_size, Directions dir, void * const ip_hdr, const unsigned short ether_type);
/*!
 * @brief       Parses layer 4 header
 * @param[out]  n   Netflow which will be filled with parsed information
 * @param[in]   dir         Packet direction
 * @param[in]   hdr Header pointer
 * @return      Layer 4 headers validity
 */
inline int parsePorts(Netflow &n, Directions dir, void *hdr);
/*!
 * @brief       Determine packet direction
 * @todo        Add IPv6 support
 *              - we don't have IPv6 address of our interface (libpcap doesn't provide it)
 *              - libpcap niether provides MAC address nor socet to find out it
 * @param[in]   ip_hdr  Pointer to IPv4 header
 * @return      Packet direction
 */
template<typename T>
Directions getPacketDirection(T *ip_hdr);
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


#include "capturing.tpp"
