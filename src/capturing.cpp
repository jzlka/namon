/** 
 *  @file       capturing.cpp
 *  @brief      Network traffic capture sources
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:45
 *  Edited:     25.03.2017 20:38
 *  Version:    1.0.0
 */

#include <map>                  //  map
#include <pcap.h>               //  pcap_lookupdev(), pcap_open_live(), pcap_dispatch(), pcap_close()
#include <mutex>                //  mutex
#include <thread>               //  thread
#include <atomic>               //  atomic::store()
#include "fileHandler.hpp"      //  initOFile()
#include "ringBuffer.hpp"       //  RingBuffer
#include "cache.hpp"            //  TEntryOrTTree
#include "netflow.hpp"          //  Netflow
#include "debug.hpp"            //  DEBUG()
#include "capturing.hpp"

#if defined(__linux__)
#include <signal.h>             //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV
#endif
#if defined(__linux__) || defined(__APPLE__)
#include <netinet/if_ether.h>   //  SIZE_ETHERNET, ETHERTYPE_IP, ETHERTYPE_IPV6, ether_header
#include <netinet/ip.h>         //  ip
#include <netinet/ip6.h>        //  ip6_hdr
#include <netinet/tcp.h>        //  tcphdr
#include <netinet/udp.h>        //  udphdr
#endif


//! Size of the ring buffer
#define RING_BUFFER_SIZE    1024

using namespace std;


// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
// https://wiki.wireshark.org/Ethernet
const unsigned char     IPV6_SIZE       =   40;     //!< Size of IPv6 header
const unsigned char     PROTO_IPV4      =   0x08;   //!< ID of IPv4 protocol
const unsigned char     PROTO_IPV6      =   0x86;   //!< ID of IPv6 protocol
const unsigned char     PROTO_UDP       =   0x11;   //!< ID of UDP protocol
const unsigned char     PROTO_TCP       =   0x06;   //!< ID of TCP protocol
const unsigned char     PROTO_UDPLITE   =   0x88;   //!< ID of UDPLite protocol

const char * g_dev = nullptr;           //!< Capturing device name
in_addr g_devIp;                        //!< Capturing device IPv4 address
ofstream oFile;                         //!< Output file stream
atomic<int> shouldStop {false};         //!< Variable which is set if program should stop



int startCapture(const char *oFilename)
{
/*
#ifdef WIN32
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)signalHandler, TRUE);
#else
*/
    signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);
/*
#endif

*/
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    try
    {
        // if the interface wasn't specified by user open the first active one
        if (g_dev == nullptr && (g_dev = pcap_lookupdev(errbuf)) == nullptr)
            throw pcap_ex("Can't open input device.",errbuf);
        uint32_t mask;
        if (pcap_lookupnet(g_dev, &g_devIp.s_addr, &mask, errbuf) == -1)
            throw pcap_ex("Can't get interface '" + string(g_dev) + "' IP address",errbuf);
        
        if ((handle = pcap_open_live(g_dev, BUFSIZ, 0, 1000, errbuf)) == NULL)
            throw pcap_ex("pcap_open_live() failed.",errbuf);
        if (pcap_setnonblock(handle, 1, errbuf) == -1)
            throw pcap_ex("pcap_setnonblock() failed.",errbuf);
        log(LogLevel::INFO, "Capturing device '", g_dev, "' was opened.");

        // Open the output file
        oFile.open(oFilename, ios::binary);
        if (!oFile)
            throw ("Can't open output file: '" + string(oFilename) + "'").c_str();
        log(LogLevel::INFO, "Output file '", oFilename, "' was opened.");
        
        // Write Section Header Block and Interface Description Block to the file
        initOFile(oFile);

        // Create ring buffer and run writing to file in a new thread
        RingBuffer<EnhancedPacketBlock> fileBuffer(RING_BUFFER_SIZE);
        thread t1 ( [&fileBuffer]() { fileBuffer.write(oFile); } );
        Cache cache;
        RingBuffer<Netflow> cacheBuffer(RING_BUFFER_SIZE);
        thread t2 ( [&cacheBuffer, &cache]() { cacheBuffer.run(&cache); } );
        
        PacketHandlerPointers ptrs { &fileBuffer, &cacheBuffer };

        while (!shouldStop)
            pcap_dispatch(handle, -1, packetHandler, reinterpret_cast<u_char*>(&ptrs));
//        if (pcap_loop(handle, -1, packetHandler, NULL) == -1)
//            throw "pcap_loop() failed";   //pcap_breakloop()?

        struct pcap_stat stats;
        pcap_stats(handle, &stats);
        pcap_close(handle);

        log(LogLevel::INFO, "Sleeping");
        this_thread::sleep_for(chrono::seconds(1)); // because of possible deadlock, get some time to return from RingBuffer::receivedPacket() to condVar.wait()
        fileBuffer.notifyCondVar(); // notify thread, it should end
        cacheBuffer.notifyCondVar(); // notify thread, it should end
        log(LogLevel::INFO, "Joining t2");
        t2.join();
        log(LogLevel::INFO, "Joining t1");
        t1.join();
        
        cout << fileBuffer.getDroppedElem() << "' packets dropped by fileBuffer." << endl;
        cout << cacheBuffer.getDroppedElem() << "' packets dropped by cacheBuffer." << endl;
        cout << stats.ps_drop << "' packets dropped by the driver." << endl;

        //! @todo save cache results into the file
    }
    catch(pcap_ex &e)
    {
        cerr << "ERROR: " << e.what() << endl;
        if (handle != nullptr) 
            pcap_close(handle);
        return EXIT_FAILURE;
    }
    catch(const char *msg) 
    {
        cerr << "ERROR: " << msg << endl;
        if (handle != nullptr) 
            pcap_close(handle);
        return EXIT_FAILURE;
    }
    return shouldStop;
} 

void packetHandler(u_char *arg_array, const struct pcap_pkthdr *header, const u_char *packet)
{    
    static Netflow n;
    static unsigned int ip_size;
    static ether_header *eth_hdr;
    PacketHandlerPointers *ptrs = reinterpret_cast<PacketHandlerPointers*>(arg_array);
    eth_hdr = (ether_header*) packet;

    RingBuffer<Netflow> *cb = ptrs->cacheBuffer;
    RingBuffer<EnhancedPacketBlock> *rb = ptrs->fileBuffer;
    if(rb->push(header, packet))
        return; //! @todo  When the packet is not saved into the output file, we don't process this packet. Valid behavior?
    
    n.setStartTime(header->ts.tv_usec);
    n.setEndTime(header->ts.tv_usec);
    
    Directions dir = getPacketDirection((ip*)(packet+ETHER_HDR_LEN), &g_devIp);
    // Parse IP header
    if (parseIp(n, ip_size, dir, (void*)(packet + ETHER_HDR_LEN), eth_hdr->ether_type))
        return;
    // Parse transport layer header
    if (parsePorts(n, dir, (void*)(packet + ETHER_HDR_LEN + ip_size)))
        return;

    if (cb->push(n))
    {
        log(LogLevel::ERROR, "Packet dropped because cache is too slow.");
        return;
    }
}


inline int parseIp(Netflow &n, unsigned int &ip_size, Directions dir, void * const ip_hdr, const unsigned short ether_type)
{
    if (ether_type == PROTO_IPV4)
    {
        const ip * const ipv4_hdr = (ip*)ip_hdr;
        ip_size = ipv4_hdr->ip_hl *4; // the length of the internet header in 32 bit words
        if (ip_size < 20)
        {
            log(LogLevel::WARNING, "Incorrect IPv4 header received.");
            return EXIT_FAILURE;
        }
        
        //! @todo reimplement to MAC address + multicast
        //! sysctl with the MIB { CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 }
        //! SIOCGIFADDR and SIOCGIFHWADDR
        //! http://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux/9436692#9436692
        in_addr* tmpIpPtr = new in_addr;
        //! @todo move constructor, memcpy is faster than move!
        if (dir == Directions::INBOUND)
            memcpy(tmpIpPtr, &ipv4_hdr->ip_dst, sizeof(in_addr));
        else
            memcpy(tmpIpPtr, &ipv4_hdr->ip_src, sizeof(in_addr));

        n.setLocalIp((void*)(tmpIpPtr));
        n.setIpVersion(4);
        n.setProto(ipv4_hdr->ip_p);
    }
    else if (ether_type == PROTO_IPV6)
    {
        log(LogLevel::ERROR, "IPv6 not implemented yet.");
        return EXIT_FAILURE;
        const ip6_hdr * const ipv6_hdr = (ip6_hdr*)ip_hdr;
        ip_size = IPV6_SIZE;
        in6_addr* tmpIpPtr = new in6_addr;

        if (dir == Directions::INBOUND)
            memcpy(tmpIpPtr, &ipv6_hdr->ip6_dst, sizeof(in6_addr));  //! @todo  Is it needed to make a copy? ipv6_hdr will be still valid when find() returns (still in packetHandler());
        else
            memcpy(tmpIpPtr, &ipv6_hdr->ip6_src, sizeof(in6_addr));  //! @todo  Is it needed to make a copy? ipv6_hdr will be still valid when find() returns (still in packetHandler());

        n.setLocalIp((void*)(tmpIpPtr));
        n.setIpVersion(6);
        n.setProto(ipv6_hdr->ip6_nxt);
    }
    else    //! @todo   What to do with 802.3?
        n.setIpVersion(0), n.setProto(0); // Netflow structure is reused with next packet so we have to delete old values. We don't care about the values other than 6,17,137, because we ignore everything except 6 (TCP) and 17 (UDP).
    //! @note   We can't determine app for IGMP, ICMP, etc. https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    return EXIT_SUCCESS;
}


inline int parsePorts(Netflow &n, Directions dir, void *hdr)
{
    switch(n.getProto())
    {
        case PROTO_TCP:
        {
            const struct tcphdr *tcp_hdr = (struct tcphdr*)hdr;
            unsigned tcp_size = tcp_hdr->th_off *4; // number of 32 bit words in the TCP header
            if (tcp_size < 20)
            {
                log(LogLevel::WARNING, "Incorrect TCP header received.");
                return EXIT_FAILURE;
            }
            if (dir == Directions::INBOUND)
                n.setLocalPort(ntohs(tcp_hdr->th_dport));
            else
                n.setLocalPort(ntohs(tcp_hdr->th_sport));
            break;
        }
        case PROTO_UDP:
        case PROTO_UDPLITE: // structure of first 4 bytes is the same (srcPort and dstPort) 
        {
            const struct udphdr *udp_hdr = (struct udphdr*)hdr;
            unsigned short udp_size = udp_hdr->uh_ulen; // length in bytes of the UDP header and UDP data
            if (udp_size < 8)
            {
                log(LogLevel::WARNING, "Incorrect UDP packet received.");
                return EXIT_FAILURE;
            }
            if (dir == Directions::INBOUND)
                n.setLocalPort(ntohs(udp_hdr->uh_dport));
            else
                n.setLocalPort(ntohs(udp_hdr->uh_sport));
            break;
        }   
        default:
            return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


void signalHandler(int signum)
{
    log(LogLevel::WARNING, "Interrupt signal (", signum, ") received.");
    shouldStop.store(signum);
}
