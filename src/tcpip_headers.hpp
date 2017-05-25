/**
 * @file       tcpip_headers.hpp
 * @brief      Protocol headers
 * @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 * @date
 *  - Created: 12.04.2017 23:21
 *  - Edited:  25.05.2017 12:57
 * @todo       rename namespace
*/

#pragma once

#include <stdint.h>		//	uint8_t, ...



namespace TOOL 
{


// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// https://wiki.wireshark.org/Ethernet

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
*                                                                            *
*                                 ETHERNET                                   *
*                                                                            *
*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#define	ETHERMTU			1500		//!< Maximum transmission unit
#define	ETHER_ADDRLEN		6			//!< Length of Ethernet address
#define ETHER_HDRLEN		14			//!< Size of Ethernet header
#define PROTO_IPv4			0x0008		//!< ID of IPv4 protocol (in network order)
#define PROTO_IPv6		0xDD86		//!< ID of IPv6 protocol (in network order)

#pragma pack(push, 1)

//! MAC address
struct mac_addr {
	unsigned char bytes[ETHER_ADDRLEN];				//!< Parts of MAC address
};

//! Ethernet header structure
struct	ether_hdr {
	uint8_t		ether_dhost[ETHER_ADDRLEN];	//!< destination MAC address
	uint8_t		ether_shost[ETHER_ADDRLEN];	//!< source MAC address
	uint16_t	ether_type;					//!< Ethernet frame type
};




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
*                                                                            *
*                                   IPv4                                     *
*                                                                            *
*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#define	IPv4_MAXPACKET		65535		//!< maximum packet size
#define IPv4_ADDRSTRLEN		16			//!< Length of IPv4 address string
#define IPv4_ADDRLEN		4			//!< Length of IPv4 address
#define AF_INET			2 //! @todo check other platforms

//! IPv4 address
struct ip4_addr {
	uint32_t addr;					//!< IPv4 address
};

//! IPv4 header structure
struct ip4_hdr {
#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__) || \
	defined(M_IX86) || defined(_M_X64) || defined(_M_IA64) || defined(_M_ARM)
	uint8_t ihl:4;
    uint8_t version:4;
#elif (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__) || defined(_M_PPC)
    uint8_t version:4;
    uint8_t ihl:4;
#else
# error "Please fix <bits/endian.h>"
    //https://stackoverflow.com/questions/4239993/determining-endianness-at-compile-time
#endif
	uint8_t   ip_tos;		/* type of service */
	uint16_t  ip_len;		/* total length */
	uint16_t  ip_id;		/* identification */
	uint16_t  ip_off;		/* fragment offset field */
	uint8_t   ip_ttl;		/* time to live */
	uint8_t   ip_p;		/* protocol */
	uint16_t  ip_sum;		/* checksum */
	ip4_addr  ip_src, ip_dst;	/* source and dest address */
};




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
*                                                                            *
*                                   IPv6                                     *
*                                                                            *
*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#define IPv6_ADDRSTRLEN	46			//!< Length of IPv6 address string
#define IPv6_ADDRLEN	16			//!< Length of IPv6 address
#define IPv6_HDRLEN		40			//!< Size of IPv6 header
#define AF_INET6	10 //! @todo check other platforms
//! @bug 23 on windows, include Ws2def.h

//! IPv6 address
struct ip6_addr {
	union {
		uint8_t   addr8[16];
		uint16_t  addr16[8];
		uint32_t  addr32[4];
	} addr;					//!< 128-bit IP6 address
};

//! IPv6 header structure
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	//!< 20 bits of flow-ID
			uint16_t ip6_un1_plen;	//!< payload length
			uint8_t  ip6_un1_nxt;	//!< next header
			uint8_t  ip6_un1_hlim;	//!< hop limit
		} ip6_un1;
		uint8_t ip6_un2_vfc;		//!< 4 bits version, top 4 bits class 
	} ip6_ctlun;
	ip6_addr ip6_src;				//!< source address
	ip6_addr ip6_dst;				//!< destination address
};

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define IP6_VERSION(ip6_hdr)	(((ip6_hdr)->ip6_vfc & 0xf0) >> 4)
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

//! @todo ipv6 - flow labels




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
*                                                                            *
*                                UDP/UDPLite                                 *
*                                                                            *
*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#define PROTO_UDP		0x11		//!< ID of UDP protocol
#define PROTO_UDPLITE	0x88		//!< ID of UDPLite protocol
#define UDP_HDRLEN		20			//!< UDP header length

//! UDP header structure
struct udp_hdr {
	uint16_t	uh_sport;			//!< source port
	uint16_t	uh_dport;			//!< destination port
	uint16_t	uh_ulen;			//!< udp length
	uint16_t	uh_sum;				//!< udp checksum
};




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
*                                                                            *
*                                    TCP                                     *
*                                                                            *
*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#define PROTO_TCP		0x06		//!< ID of TCP protocol

//! TCP header structure
struct tcp_hdr {
	uint16_t	th_sport;			//!< source port
	uint16_t	th_dport;			//!< destination port
	uint32_t	th_seq;				//!< sequence number
	uint32_t	th_ack;				//!< acknowledgement number
#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__) || defined(_M_PPC)
        uint8_t	th_x2:4;            //!< (unused)
        uint8_t	th_off:4;           //!< data offset
#endif
#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__) || \
	defined(M_IX86) || defined(_M_X64) || defined(_M_IA64) || defined(_M_ARM)
       // uint8_t	th_off:4;           //!< data offset
       // uint8_t	th_x2:4;            //!< (unused)
       //! @todo repair
		uint8_t	th_x2 : 4;            //!< (unused)
		uint8_t	th_off : 4;           //!< data offset
#endif
	uint8_t		th_flags;
	uint16_t	th_win;				//!< window
	uint16_t	th_sum;				//!< checksum
	uint16_t	th_urp;				//!< urgent pointer
};

#pragma pack(pop)


}	// namespace TOOL
