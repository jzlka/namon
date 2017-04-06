/**
 *  @file       capturing.cpp
 *  @brief      Network traffic capture sources
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:45
 *   - Edited:  06.04.2017 18:50
 *   @todo      IPv6 implementation
 *   @todo      Comment which functions move classes
 *   @todo      What to do when the cache contains invalid record and getInode returns inode == 0
 *              Save it to cache or the packet belongs to the old record?
 *   @todo      Is it a good idea to have opened /proc/net files for the whole time? or open it for every unknown packet?
 *   @todo      Broadcast and multicast packets (239.255.255.250, 0.0.0.0, 224.0.0.7, 1.13.0.0, 192.168.1.255)
 *   @bug       Getting packets with local port set to 0 in determineApp()
 *   @bug       Some endTimes are set to earlier time than startTimes in Netflow
 *   @bug       Sometimes deadlock after ^C
 *   @bug       Saved time is not a packet time, but capture time (?)
 *   @todo      getting incorrect udp packet err
 *   @todo      save packet timestamp
 *   @bug       wireshark: damaged pcap-ng output file
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
#include "debug.hpp"            //  D()
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

using namespace std;


// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
// https://wiki.wireshark.org/Ethernet
const unsigned char     IPV6_SIZE               =   40;     //!< Size of IPv6 header
const unsigned char     PROTO_IPV4              =   0x08;   //!< ID of IPv4 protocol
const unsigned char     PROTO_IPV6              =   0x86;   //!< ID of IPv6 protocol
const unsigned char     PROTO_UDP               =   0x11;   //!< ID of UDP protocol
const unsigned char     PROTO_TCP               =   0x06;   //!< ID of TCP protocol
const unsigned char     PROTO_UDPLITE           =   0x88;   //!< ID of UDPLite protocol
const unsigned int      FILE_RING_BUFFER_SIZE   =   2000;   //!< Size of the ring buffer
const unsigned int      CACHE_RING_BUFFER_SIZE  =   2000;   //!< Size of the ring buffer

map<string, vector<Netflow *>> g_finalResults;  //!< Applications and their netflows
const char * g_dev = nullptr;                   //!< Capturing device name
mac_addr g_devMac {{0}};                          //!< Capturing device MAC address
const mac_addr g_macMcast4 {{0x01,0x00,0x5e}};    //!< IPv4 multicast MAC address
const mac_addr g_macMcast6 {{0x33,0x33}};         //!< IPv6 multicast MAC address
const mac_addr g_macBcast {{0xff,0xff,0xff}};     //!< Broadcast MAC address
vector<in_addr*> g_devIps;                      //!< Capturing device IPv4 address
ofstream oFile;                                 //!< Output file stream
atomic<int> shouldStop {false};                 //!< Variable which is set if program should stop
unsigned int rcvdPackets = 0;                   //!< Number of received packets
unsigned int g_notFoundInodes = 0;              //!< Number of unsuccessful searches for inode number
unsigned int g_notFoundApps = 0;                //!< Number of unsuccessful searches for application



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

        // get interface IP
        pcap_if_t *alldevs;
        int status = pcap_findalldevs(&alldevs, errbuf);
        if(status != 0)
            throw pcap_ex("pcap_findalldevs() error.", errbuf);
        for(pcap_if_t *d=alldevs; d!=NULL; d=d->next)
        {
            if (strcmp(g_dev, d->name))
                continue;

            for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next)
            {
                if(a->addr->sa_family == AF_INET)
                {
                    in_addr* ip = new in_addr;
                    *ip = ((struct sockaddr_in*)a->addr)->sin_addr;
                    g_devIps.push_back(ip);
                }
                else
                    ;//throw "IPv6 is not implemented yet"; //! @todo implement
            }
        }
        pcap_freealldevs(alldevs);

	// get interface MAC address
	setDevMac();

        if ((handle = pcap_open_live(g_dev, BUFSIZ, false, 1000, errbuf)) == NULL)
            throw pcap_ex("pcap_open_live() failed.",errbuf);
        if (pcap_setnonblock(handle, 1, errbuf) == -1)
            throw pcap_ex("pcap_setnonblock() failed.",errbuf);
        log(LogLevel::INFO, "Capturing device '", g_dev, "' was opened.");

        // Open the output file
        oFile.open(oFilename, ios::binary);
        if (!oFile)
            throw ("Can't open output file: '" + string(oFilename) + "'").c_str();
        log(LogLevel::INFO, "Output file '", oFilename, "' was opened.");

        // Write Section Header Block and Interface Description Block to the output file
        initOFile(oFile);

        // Create ring buffer and run writing to file in a new thread
        RingBuffer<EnhancedPacketBlock> fileBuffer(FILE_RING_BUFFER_SIZE);
        thread t1 ( [&fileBuffer]() { fileBuffer.write(oFile); } );
        Cache cache;
        RingBuffer<Netflow> cacheBuffer(CACHE_RING_BUFFER_SIZE);
        thread t2 ( [&cacheBuffer, &cache]() { cacheBuffer.run(&cache); } );

        PacketHandlerPointers ptrs { &fileBuffer, &cacheBuffer };

        log(LogLevel::INFO, "Capturing...");
        while (!shouldStop)
            pcap_dispatch(handle, -1, packetHandler, reinterpret_cast<u_char*>(&ptrs));
//        if (pcap_loop(handle, -1, packetHandler, NULL) == -1)
//            throw "pcap_loop() failed";   //pcap_breakloop()?

        struct pcap_stat stats;
        pcap_stats(handle, &stats);
        pcap_close(handle);

        log(LogLevel::INFO, "Waiting for threads to finish.");
        this_thread::sleep_for(chrono::seconds(1)); // because of possible deadlock, get some time to return from RingBuffer::receivedPacket() to condVar.wait()
        fileBuffer.notifyCondVar(); // notify thread, it should end
        cacheBuffer.notifyCondVar(); // notify thread, it should end
        t2.join();
        t1.join();

        cache.saveResults();
        CustomBlock cBlock;
        cBlock.write(oFile);

        /******* SUMMARY *******/
        cout << fileBuffer.getDroppedElem() << "' packets dropped by fileBuffer." << endl;
        cout << cacheBuffer.getDroppedElem() << "' packets dropped by cacheBuffer." << endl;
        cout << stats.ps_drop << "' packets dropped by the driver." << endl;
        cout << "Total " << rcvdPackets << " packets received.\n" << endl;

        cout << "Total " << g_finalResults.size() << " second level entries (same local port)" << endl;
        cout << "Inode not found for " << g_notFoundInodes << " ports." << endl;
        cout << "Application not found for " << g_notFoundApps << " inodes." << endl;
        cout << g_finalResults.size() << " applications in total:" << endl;
        for (auto record : g_finalResults)
        {
            cout << "  * " << record.first << endl;
            for (auto entry : record.second)
                delete entry;
        }
        cout << "Cache records: " << endl;
        cache.print();
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

    rcvdPackets++;
    if(rb->push(header, packet))
    {
        log(LogLevel::ERROR, "Packet dropped because of slow hard drive.");
        return; //! @todo  When the packet is not saved into the output file, we don't process this packet. Valid behavior?
    }
    //! @todo What to do with 802.3?
    // We can't determine app for IGMP, ICMP, etc. https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    if (eth_hdr->ether_type != PROTO_IPV4 && eth_hdr->ether_type != PROTO_IPV6)
        return;
    

    n.setStartTime(header->ts.tv_usec);
    n.setEndTime(header->ts.tv_usec);

    Directions dir = getPacketDirection(eth_hdr);
    if (dir == Directions::UNKNOWN)
        return;
    // Parse IP header
    if (parseIp(n, ip_size, dir, (void*)(packet + ETHER_HDR_LEN), eth_hdr->ether_type))
        return;
    // Parse transport layer header
    if (parsePorts(n, dir, (void*)(packet + ETHER_HDR_LEN + ip_size)))
        return;
    // STD::MOVE Netflow into buffer
    if (cb->push(n))
    {
        log(LogLevel::ERROR, "Packet dropped because cache is too slow.");
        return;
    }
}


Directions getPacketDirection(ether_header *eth_hdr)
{
    if (memcmp(&g_devMac, eth_hdr->ether_shost, sizeof(mac_addr)) == 0)
        return Directions::OUTBOUND;
    else if (memcmp(&g_devMac, eth_hdr->ether_dhost, sizeof(mac_addr)) == 0)
        return Directions::INBOUND;
    // else compare multicast and broadcast address
    // we don't have have to compare second part of the mac address
    // because as we don't capture in promiscuous mode we won't receive
    // multicast packet with not our second part the of mac address
    // multicast/broadcast as destination == INBOUND
    else if (memcmp(&g_macMcast4, eth_hdr->ether_dhost, 3) == 0
        || memcmp(&g_macMcast6, eth_hdr->ether_dhost, 2) == 0
        || memcmp(&g_macBcast, eth_hdr->ether_dhost, 3) == 0)
        return Directions::INBOUND;
    // multicast/broadcast as source IP is not valid

    D_ARRAY((const unsigned char*)&g_devMac.bytes, 6);
    D_ARRAY(eth_hdr->ether_shost, 6);
    D_ARRAY(eth_hdr->ether_dhost, 6);
    log(LogLevel::ERROR, "Can't determine packet direction.");
    return Directions::UNKNOWN;
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
        if (dir == Directions::INBOUND)
            tmpIpPtr->s_addr = ipv4_hdr->ip_dst.s_addr;
        else
            tmpIpPtr->s_addr = ipv4_hdr->ip_src.s_addr;
        n.setLocalIp((void*)(tmpIpPtr));

        n.setIpVersion(4);
        n.setProto(ipv4_hdr->ip_p);
    }
    else
    {
        log(LogLevel::ERROR, "IPv6 is not implemented yet."); // we can't determine packet direction
        return EXIT_FAILURE;
        const ip6_hdr * const ipv6_hdr = (ip6_hdr*)ip_hdr;
        ip_size = IPV6_SIZE;
        in6_addr* tmpIpPtr = new in6_addr;

        if (dir == Directions::INBOUND)
            memcpy(tmpIpPtr, &ipv6_hdr->ip6_dst, sizeof(in6_addr));
        else
            memcpy(tmpIpPtr, &ipv6_hdr->ip6_src, sizeof(in6_addr));

        n.setLocalIp((void*)(tmpIpPtr));
        n.setIpVersion(6);
        n.setProto(ipv6_hdr->ip6_nxt);
    }
    return EXIT_SUCCESS;
}


//! @todo proto can be set to 0 -> arp/rarp
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
