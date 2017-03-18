/** 
 *  @file		capturing.cpp
 *  @brief      Network traffic capture sources
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:45
 *  Edited:		17.03.2017 12:37
 *  Version:    1.0.0
 *  @todo       set direction in netflow
 *  @todo       set startTime in netflow
 */

#include <iostream>             //  cerr, endl
#include <fstream>              //  fstream
#include <map>                  //  map
#include <pcap.h>               //  pcap_lookupdev(), pcap_open_live(), pcap_dispatch(), pcap_close()
#include "netflow.hpp"          //  Netflow
#include "debug.hpp"            //  DEBUG()
#include "fileHandler.hpp"      //  initOFile()
#include "cache.hpp"            //  TEntryOrTTree
#include "capturing.hpp"

#if defined(__linux__)
#include "tool_linux.hpp"
#include <signal.h>             //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV
#include <netinet/if_ether.h>   //  SIZE_ETHERNET, ETHERTYPE_IP, ETHERTYPE_IPV6, ether_header
#include <netinet/ip.h>         //  ip
#include <netinet/ip6.h>        //  ip6_hdr
#include <netinet/tcp.h>        //  tcphdr
#include <netinet/udp.h>        //  udphdr
#endif
#if defined(__FreeBSD__)
#include "tool_bsd.hpp"
//#include <in.h>
//#include <arpa/inet.h>
#endif
#if defined(__APPLE__)
#include "tool_apple.hpp"
#include <netinet/if_ether.h>   //  SIZE_ETHERNET, ETHERTYPE_IP, ETHERTYPE_IPV6, ether_header
#include <netinet/ip.h>         //  ip
#include <netinet/ip6.h>        //  ip6_hdr
#include <netinet/tcp.h>        //  tcphdr
#include <netinet/udp.h>        //  udphdr
#endif
#if defined(WIN32) || defined(WINx64) || (defined(__MSDOS__) || defined(__WIN32__))
#include "tool_win.hpp"
//#include <winsock2.h>
//#include <ws2tcpip.h>
#endif

#define RING_BUFFER_SIZE    1024

using namespace std;


// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
// https://wiki.wireshark.org/Ethernet
const unsigned char     IPV6_SIZE       =   40;
const unsigned char     PROTO_IPV4      =   0x08;
const unsigned char     PROTO_IPV6      =   0x86;
const unsigned char     PROTO_UDP       =   0x11;
const unsigned char     PROTO_TCP       =   0x06;
const unsigned char     PROTO_UDPLITE   =   0x88;

const char * g_dev = "Not specified";   //!< Capturing device
ofstream oFile;                         //!< Output file stream
unsigned long g_droppedPackets;         //!< Number of dropped packets during capture
int shouldStop = false;                 //!< Variable which is set if program should stop
mutex m_shouldStopVar;                  //!< Mutex used to lock #shouldStop variable



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
        
        if ((handle = pcap_open_live(g_dev, BUFSIZ, 0, 1000, errbuf)) == NULL)
            throw pcap_ex("pcap_open_live() failed.",errbuf);
        if (pcap_setnonblock(handle, 1, errbuf) == -1)
            throw pcap_ex("pcap_setnonblock() failed.",errbuf);
        log(LogLevel::INFO, "Capturing device '", g_dev, "' was opened.");

        // Open the output file
        oFile.open(oFilename);
        if (!oFile)
            throw "Can't open output file: '" + string(oFilename) + "'";
        log(LogLevel::INFO, "Output file '", oFilename, "' was opened.");
        
        // Write Section Header Block and Interface Description Block to the file
        initOFile(oFile);

        // Create ring buffer and run writing to file in a new thread
        RingBuffer rb(RING_BUFFER_SIZE);
        thread t1 ( [&rb]() { rb.write(); } );

        //Create cache and periodically refresh it in a new thread;
        Cache cache;
        thread t2 ( [&cache]() { cache.periodicUpdate(); } );
        // TODO wait for cache to initialize
        
        void *arg_arr[2] = { &rb, &cache};

        while (!stop())
            pcap_dispatch(handle, -1, packetHandler, reinterpret_cast<u_char*>(arg_arr));
//        if (pcap_loop(handle, -1, packetHandler, NULL) == -1)
//            throw "pcap_loop() failed";   //pcap_breakloop()?

        this_thread::sleep_for(chrono::seconds(1)); // because of possible deadlock, get some time to return from RingBuffer::receivedPacket() to condVar.wait()
        rb.notifyCondVar(); // notify thread, it should end
        t2.join();
        t1.join();
    
        log(LogLevel::INFO, "Dropped '", g_droppedPackets, "' packets.");
        pcap_close(handle);
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
        return EXIT_FAILURE;
    }
    return stop();
}


void packetHandler(u_char *arg_array, const struct pcap_pkthdr *header, const u_char *packet)
{    
    static Netflow n(g_dev);
    static unsigned int ip_size;
    static ether_header *eth_hdr;
    void ** arg_arr = reinterpret_cast<void**>(arg_array);
    n.setStartTime(header->ts.tv_usec);

    eth_hdr = (ether_header*) packet;
    Cache *cache = static_cast<Cache *>(arg_arr[1]);    // TODO: global variable?
    RingBuffer *rb = static_cast<RingBuffer *>(arg_arr[0]);    // TODO: global variable?
    if(rb->push(header, packet))
    {
        g_droppedPackets++;
        return; //TODO ok?
    }
    
    // Parse IP header
    if (parseIp(n, ip_size, (void*)(packet + ETHER_HDR_LEN), eth_hdr->ether_type))
        return;

    // Parse transport layer header
    if (parsePorts(n, (void*)(packet + ETHER_HDR_LEN + ip_size)))
        return;

    // find out if it belongs to this computer (promiscuous mode)

    TEntryOrTTree *cacheRecord = cache->find(n);
    if (cacheRecord != nullptr && cacheRecord->isEntry())
        static_cast<TEntry *>(cacheRecord)->getNetflowPtr()->setEndTime(header->ts.tv_usec);
    else    // either TTree or nullptr
        ;// TODO what to do? vector of unknown netflows?
    // We can't call to update cache because in this second there can be thousands
    // of the same packets and everyone would call to update cache.
    // We have to save startTime

    D("srcPort:" << n.getSrcPort() << ", dstPort:" << n.getDstPort() << ", proto:" << (int)n.getProto());
}


inline int parseIp(Netflow &n, unsigned int &ip_size, void * const ip_hdr, const unsigned short ether_type)
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
        in_addr* tmpSrcIpPtr = new in_addr;
        memcpy(tmpSrcIpPtr, &ipv4_hdr->ip_src, sizeof(in_addr));
        in_addr* tmpDstIpPtr = new in_addr;
        memcpy(tmpDstIpPtr, &ipv4_hdr->ip_dst, sizeof(in_addr));
        n.setSrcIp((void*)(tmpSrcIpPtr));
        n.setDstIp((void*)(tmpDstIpPtr));
        n.setIpVersion(4);
        n.setProto(ipv4_hdr->ip_p);
    }
    else if (ether_type == PROTO_IPV6)
    {
        const ip6_hdr * const ipv6_hdr = (ip6_hdr*)ip_hdr;
        ip_size = IPV6_SIZE;
        in6_addr* tmpSrcIpPtr = new in6_addr;
        memcpy(tmpSrcIpPtr, &ipv6_hdr->ip6_src, sizeof(in6_addr));  // TODO is it needed to copy? packetHandler won't returnoso ipv6_hdr will be still valid when find() returns;
        in6_addr* tmpDstIpPtr = new in6_addr;
        memcpy(tmpDstIpPtr, &ipv6_hdr->ip6_dst, sizeof(in6_addr));
        n.setSrcIp((void*)(tmpSrcIpPtr));
        n.setDstIp((void*)(tmpDstIpPtr));
        n.setIpVersion(6);
        n.setProto(ipv6_hdr->ip6_nxt);
    }
    else    // TODO what to do with 802.3?
        n.setIpVersion(0), n.setProto(0); // Netflow structure is reused with next packet so we have to delete old value. We don't care about the value, because we ignore everything except 6 (TCP) and 17 (UDP).
    // NOTE: we can't determine app for IGMP, ICMP, etc. https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    return EXIT_SUCCESS;
}


inline int parsePorts(Netflow &n, void *hdr)
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
            n.setSrcPort(ntohs(tcp_hdr->th_sport));
            n.setDstPort(ntohs(tcp_hdr->th_dport));
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
            n.setSrcPort(ntohs(udp_hdr->uh_sport));
            n.setDstPort(ntohs(udp_hdr->uh_dport));
            break;
        }   
        default:
            return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


bool stop()
{
    lock_guard<mutex> guard(m_shouldStopVar);
    return shouldStop;
}


void signalHandler(int signum)
{
    log(LogLevel::WARNING, "Interrupt signal (", signum, ") received.");
    lock_guard<mutex> guard(m_shouldStopVar);
    shouldStop = signum;
}



