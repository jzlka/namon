/** 
 *  @file       capturing.hpp
 *  @brief      Network traffic capture header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:48
 *   - Edited:  23.06.2017 12:00
 */

#pragma once

#include <iostream>             //  exception, string
#include <sys/types.h>          //  u_char
#include <atomic>               //  atomic

#include "tcpip_headers.hpp"	//	ether_hdr
#include "netflow.hpp"			//	Netflow
#include "ringBuffer.hpp"		//	RingBuffer
#include "pcapng_blocks.hpp"	//	EnhancedPackedBlock
#include "cache.hpp"			//	TEntry
#include "debug.hpp"            //  log()


using NAMON::ip4_addr;
using NAMON::ether_hdr;
using NAMON::Netflow;
using NAMON::TEntry;
using NAMON::EnhancedPacketBlock;
using NAMON::RingBuffer;


//! Size of a libpcap error buffer
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

extern std::atomic<int> shouldStop;

/*!
* An enum representing packet flow direction
*/
enum class Directions {
	OUTBOUND, //!< Outgoing packets
	INBOUND,  //!< Incoming packets
	UNKNOWN,  //!< Direction is not known
};

/*!
* @struct  PacketHandlerParams
* @brief   Struct used to pass packetHandler more pointers in one argument
*/
struct PacketHandlerParams
{
	//! @brief  Default c'tor that sets pointers with parameters
	PacketHandlerParams(RingBuffer<EnhancedPacketBlock> *fb, RingBuffer<Netflow> *cb)
		: fileBuffer(fb), cacheBuffer(cb) {}
	RingBuffer<EnhancedPacketBlock> *fileBuffer = nullptr; //!< Pointer to RingBuffer which will be written to a file
	RingBuffer<Netflow> *cacheBuffer = nullptr;            //!< Used cache
};



/*!
* @brief       Determines packet derection
* @param[in]   eth_hdr   Ethernet header
* @return      Returns NAMON::Direction
*/
Directions getPacketDirection(NAMON::ether_hdr *eth_hdr);
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
void packetHandler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *bytes);
/*!
* @brief       Parses IP header
* @param[out]  n           Netflow which will be filled with parsed information
* @param[out]  ip_size     Size of the IP header
* @param[in]   dir         Packet direction
* @param[in]   ip_hdr      Pointer to the IP header
* @param[in]   ether_type  Ethernet frame type
* @return      IP header's validity
*/
inline int parseIp(Netflow &n, unsigned int &ip_size, Directions dir, void * const ip_hdr, const unsigned short ether_type);
/*!
* @brief       Parses layer 4 header
* @param[out]  n   Netflow which will be filled with parsed information
* @param[in]   dir Packet direction
* @param[in]   hdr Header pointer
* @return      Layer 4 header validity
*/
inline int parsePorts(Netflow &n, Directions dir, void *hdr);
/*!
* @brief       Signal handler function
* @param[in]   signum  Received interrupt signal
*/
void signalHandler(int signum);



/*!
* @class   pcap_ex
* @brief   Exception used during pcap related errors
*/
struct pcap_ex : public std::exception
{
	std::string msg;
public:
	pcap_ex(const std::string &m, const char *errbuf) : msg(m + "\nlibpcap: " + errbuf) {}
	const char *what() const throw()
	{
		return msg.c_str();
	}
};
