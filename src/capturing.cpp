/**
 *  @file       capturing.cpp
 *  @brief      Network traffic capture sources
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:45
 *   - Edited:  20.05.2017 21:09
 *   @todo      determine platform in scripts
 *   @todo      IPv6 implementation tests
 *   @todo      EnhancedPacketBlock disable pragma 1 -> speed up working with ringBuffer?
 *   @todo      raw sockets in procfs
 *   @todo      What to do when the cache contains invalid record and getInode returns inode == 0
 *              Save it to cache or the packet belongs to the old record?
 *   @todo      Broadcast and multicast packets (239.255.255.250, 0.0.0.0, 224.0.0.7, 1.13.0.0, 192.168.1.255) -> use address 0.0.0.0 instead?
 *   @todo      getting incorrect udp packet err
 *   @todo      os_version_info from Wireshark
 *   @bug       cal_init leak
 *   @bug       ipv6 proc/net files does not have always same format, reimplement
 *   @bug       cache contains records where inode == 0 && appName != ""
 *   @bug       Getting packets with local port set to 0 in determineApp() (and also zero IP)
 *   @bug       Sometimes deadlock after ^C (when there is too many log messages)
 *   @bug       2 sockets (UDP, :68, eth0(INADDR_ANY), eth1(INADDR_ANY)), 2 application instances (dhclient), 
 *              2 inodes, 2 interfaces, 2 procfs entries
 *
 *              sl  local_address rem_address   st  ...   uid  timeout inode ref pointer drops
 *              458: 00000000:0044 00000000:0000 07 ...    0        0  13021 2   f6cbe300 0 (eth0)
 *              458: 00000000:0044 00000000:0000 07 ...    0        0  14400 2   f3fe6e40 0 (eth1)
 *              
 *              ->cache stores only first inode for both instances
 *              ->mozme to vyuzit ako utok? originalna aplikacia komunikuje na rozhrani, porte a my otvorime addr_any na tom istom porte a budeme to tiez prijimat?
 *   @todo      Add end of levels entry to the TreeLevel
 *   @todo      Pridat kazdemu vlaknu svoju cond variable a nech zamkne mutex ked kontroluje shouldStop
 *   @todo      upravit determineApp() aby vracal ukazatel s naplnenym TEntry
 *   @bug       Asi nepracuje na wlan rozhraniach
 *   @bug       Windows appname is enclosed in quotes and argument delimiter is space - convert it
 *   @bug       cant capture using npcap on windows 7, firstly wireshark must be run
 *   @bug       catch exception in case of full disk
 *   @bug       add check ending '\0' in appname
 */

#include <map>                  //  map
#include <pcap.h>               //  pcap_lookupdev(), pcap_open_live(), pcap_dispatch(), pcap_close()
#include <thread>               //  thread
#include <atomic>               //  atomic::store()

#if defined(__linux__)
#include <signal.h>             //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV
#include "tool_linux.hpp"		//	setDevMac()

#elif defined(__APPLE__)
#include "tool_apple.hpp"		//	setDevMac()

#elif defined(_WIN32)
//#include <Windows.h>			//	SetConsoleCtrlHandler()
#include <signal.h>			//	signal()
#include "tool_win.hpp"			//	setDevMac()
#endif

#include "tcpip_headers.hpp"	//	
#include "fileHandler.hpp"      //  initOFile()
#include "ringBuffer.hpp"       //  RingBuffer
#include "cache.hpp"            //  TEntryOrTTree
#include "netflow.hpp"          //  Netflow
#include "debug.hpp"            //  D(), log()
#include "utils.hpp"            //  
#include "capturing.hpp"


#if defined(_WIN32)
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")
//#pragma comment(lib, "Ws2_32.lib")	//	ntohs()
#endif


using namespace TOOL;


const unsigned int      FILE_RING_BUFFER_SIZE	= 2000;   //!< Size of the ring buffer
const unsigned int      CACHE_RING_BUFFER_SIZE	= 2000;   //!< Size of the ring buffer
const mac_addr			g_macMcast4				{ { 0x01,0x00,0x5e } };					//!< IPv4 multicast MAC address
const mac_addr			g_macMcast6				{ { 0x33,0x33 } };						//!< IPv6 multicast MAC address
const mac_addr			g_macBcast				{ { 0xff,0xff,0xff,0xff,0xff,0xff } };  //!< Broadcast MAC address

map<string, vector<Netflow *>> g_finalResults;			//!< Applications and their netflows
pcap_t *g_pcapHandle			= nullptr;              //!< Pcap handle
const char * g_dev				= nullptr;              //!< Capturing device name
mac_addr g_devMac				{ {0} };				//!< Capturing device MAC address
ofstream oFile;											//!< Output file stream
atomic<int> shouldStop			{ false };              //!< Variable which is set if program should stop
unsigned int rcvdPackets		= 0;					//!< Number of received packets
unsigned int g_allSockets		= 0;					//!< Number of unique sockets
unsigned int g_notFoundSockets	= 0;					//!< Number of unsuccessful searches for inode number
unsigned int g_notFoundApps		= 0;					//!< Number of unsuccessful searches for application



int startCapture(const char *oFilename)
{

#if 0 //def _WIN32
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)signalHandler, TRUE);
#else
	signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
	signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);
#endif

	char errbuf[PCAP_ERRBUF_SIZE];

	try
	{
		// if the interface wasn't specified by user open the first active one
		//if (g_dev == nullptr && (g_dev = pcap_lookupdev(errbuf)) == nullptr)
		//	throw pcap_ex("Can't open input device.", errbuf);

		pcap_if_t *alldevs, *d;
		u_int inum, i = 0;

		/* The user didn't provide a packet source: Retrieve the device list */
		if (g_dev == nullptr)
		{
			if (pcap_findalldevs(&alldevs, errbuf) == -1)
				throw pcap_ex("Can't open input device.", errbuf);

			/* Print the list */
			for (d = alldevs; d; d = d->next)
			{
				cout << ++i << ": " << d->name << "\t";
				cout << (d->description ? d->description : "(No description available)") << endl;
			}

			if (i == 0)
				throw "No interfaces found! Make sure npcap/libpcap is installed.";

			cout << "Enter the interface number (1-" << i << "): ";
			cin >> inum;

			if (inum < 1 || inum > i)
				throw "Interface number out of range.";

			/* Jump to the selected adapter */
			for (d = alldevs, i = 0; i < inum-1; d = d->next, i++)
				;
			g_dev = d->name;
		}

		// get interface MAC address
		if (setDevMac())
			throw "Can't get interface MAC address.";

		
		// Open the output file
		oFile.open(oFilename, ios::binary);
		if (!oFile)
			throw ("Can't open output file: '" + string(oFilename) + "'").c_str();
		log(LogLevel::INFO, "Output file '", oFilename, "' was opened.");

		// Write Section Header Block and Interface Description Block to the output file
		if (initOFile(oFile))
			throw "Output file initialization error.";
#if defined(_WIN32)
        if (connectToWmi())
            throw "Connection to WMI failed";
#endif

		if ((g_pcapHandle = pcap_open_live(g_dev, BUFSIZ, false, 1000, errbuf)) == NULL)
			throw pcap_ex("pcap_open_live() failed.", errbuf);
		//Aif (pcap_setnonblock(g_pcapHandle, 1, errbuf) == -1)
		//A	throw pcap_ex("pcap_setnonblock() failed.", errbuf);
		log(LogLevel::INFO, "Capturing device '", g_dev, "' was opened.");

		// Create ring buffer and run writing to file in a new thread
		RingBuffer<EnhancedPacketBlock> fileBuffer(FILE_RING_BUFFER_SIZE);
		thread t1([&fileBuffer]() { fileBuffer.write(oFile); });
		Cache cache;
		RingBuffer<Netflow> cacheBuffer(CACHE_RING_BUFFER_SIZE);
		/*X*/thread t2([&cacheBuffer, &cache]() { cacheBuffer.run(&cache); });

		PacketHandlerParams ptrs{ &fileBuffer, &cacheBuffer };
		
        log(LogLevel::INFO, "Capturing...");
		//Awhile (!shouldStop)
		//A    pcap_dispatch(handle, -1, packetHandler, reinterpret_cast<u_char*>(&ptrs));
		if (pcap_loop(g_pcapHandle, -1, packetHandler, reinterpret_cast<u_char*>(&ptrs)) == -1)
			throw "pcap_loop() failed"; //! @todo what to do with threads

		struct pcap_stat stats;
		pcap_stats(g_pcapHandle, &stats);

		pcap_close(g_pcapHandle);

		log(LogLevel::INFO, "Waiting for threads to finish.");
		this_thread::sleep_for(chrono::seconds(1)); // because of possible deadlock, get some time to return from RingBuffer::receivedPacket() to condVar.wait()
		fileBuffer.notifyCondVar(); // notify thread, it should end
		/*X*/cacheBuffer.notifyCondVar(); // notify thread, it should end
		/*X*/t2.join();
		t1.join();

#if defined(_WIN32)
        cleanWmiConnection();
#endif
		/*X*/cache.saveResults();
		/*X*/CustomBlock cBlock;
		/*X*/cBlock.write(oFile); //! @todo do not use CustomBlock class

		/******* SUMMARY *******/
		cout << fileBuffer.getDroppedElem() << "' packets dropped by fileBuffer." << endl;
		cout << cacheBuffer.getDroppedElem() << "' packets dropped by cacheBuffer." << endl;
		cout << stats.ps_drop << "' packets dropped by the driver." << endl;

#ifdef DEBUG_BUILD
		cout << "Total " << rcvdPackets << " packets received.\n" << endl;
		cout << "Total " << g_finalResults.size() << " records with exactly the same 3-tuple" << endl;
		cout << "Inode not found for " << g_notFoundSockets << " ports from " << g_allSockets << "." << endl;
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
#endif
#ifdef _WIN32
		if (cin.fail())
        {
			cin.clear();
			cin.ignore(INT_MAX, '\n'); //INT_MAX is used instead of numeric_limits<streamsize>::max because of max() define in minwindef.h
		}
		cout << "Enter any symbol to exit...";
		int x;
		cin >> x;
#endif
	}
	catch (pcap_ex &e)
	{
		cerr << "ERROR: " << e.what() << endl;
		if (g_pcapHandle)
			pcap_close(g_pcapHandle);
		return EXIT_FAILURE;
	}
	catch (const char *msg)
	{
		cerr << "ERROR: " << msg << endl;
		if (g_pcapHandle)
			pcap_close(g_pcapHandle);
		return EXIT_FAILURE;
	}
	return shouldStop;
}

void packetHandler(unsigned char *arg_array, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	static Netflow n;
	static unsigned int ip_hdrlen;
	static ether_hdr *eth_hdr;
	PacketHandlerParams *ptrs = reinterpret_cast<PacketHandlerParams*>(arg_array);

	RingBuffer<Netflow> *cb = ptrs->cacheBuffer;
	RingBuffer<EnhancedPacketBlock> *rb = ptrs->fileBuffer;
	eth_hdr = (ether_hdr*)packet;

	rcvdPackets++;
	if (rb->push(header, packet))
	{
		log(LogLevel::ERR, "Packet dropped because of slow hard drive.");
		return; //! @todo  When the packet is not saved into the output file, we don't process this packet. Valid behavior?
	}
	//! @todo What to do with 802.3?
	// We can't determine app for IGMP, ICMP, etc. https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	if (eth_hdr->ether_type != PROTO_IPv4 && eth_hdr->ether_type != PROTO_IPv6)
		return;

	uint64_t usecUnixTime = header->ts.tv_sec * (uint64_t)1000000 + header->ts.tv_sec;
	n.setStartTime(usecUnixTime);
	n.setEndTime(usecUnixTime);

	Directions dir = getPacketDirection(eth_hdr);
	if (dir == Directions::UNKNOWN)
		return;
	// Parse IP header
	if (parseIp(n, ip_hdrlen, dir, (void*)(packet + ETHER_HDRLEN), eth_hdr->ether_type))
		return;
	// Parse transport layer header
	if (parsePorts(n, dir, (void*)(packet + ETHER_HDRLEN + ip_hdrlen)))
	{
	//		if (n.getIpVersion() == 4)
	//			delete static_cast<ip4_addr*>(n.getLocalIp());
	//		else
	//			delete static_cast<ip6_addr*>(n.getLocalIp());
		return;
	}
	// STD::MOVE Netflow into buffer
	/*X*/if (cb->push(n))
	/*X*/{
	/*X*/	log(LogLevel::ERR, "Packet dropped because cache is too slow.");
	/*X*/	return;
	/*X*/}
}


Directions getPacketDirection(ether_hdr *eth_hdr)
{
	if (memcmp(&g_devMac, eth_hdr->ether_shost, sizeof(mac_addr)) == 0)
		return Directions::OUTBOUND;
	else if (memcmp(&g_devMac, eth_hdr->ether_dhost, sizeof(mac_addr)) == 0)
		return Directions::INBOUND;
	// else compare multicast and broadcast address
	// we don't have have to compare second part of the mac address
	// because we don't capture in promiscuous mode so we won't receive
	// multicast packet with not our second part the of mac address
	// multicast/broadcast as destination == INBOUND
	else if (memcmp(&g_macMcast4, eth_hdr->ether_dhost, 3) == 0
		|| memcmp(&g_macMcast6, eth_hdr->ether_dhost, 2) == 0
		|| memcmp(&g_macBcast, eth_hdr->ether_dhost, 6) == 0)
		return Directions::INBOUND;
	// multicast/broadcast as source IP is not valid

	D("int vs. src vs. dst");
	D_ARRAY((const unsigned char*)&g_devMac.bytes, 6);
	D_ARRAY(eth_hdr->ether_shost, 6);
	D_ARRAY(eth_hdr->ether_dhost, 6);
	log(LogLevel::ERR, "Can't determine packet direction.");
	return Directions::UNKNOWN;
}


inline int parseIp(Netflow &n, unsigned int &ip_size, Directions dir, void * const ip_hdr, const unsigned short ether_type)
{
	if (ether_type == PROTO_IPv4)
	{
		const ip4_hdr * const hdr = (ip4_hdr*)ip_hdr;
		ip_size = hdr->ihl * 4; // the length of the internet header in 32 bit words
		if (ip_size < 20)
		{
			log(LogLevel::WARNING, "Incorrect IPv4 header received.");
			return EXIT_FAILURE;
		}

		ip4_addr* tmpIpPtr = new ip4_addr;
		if (dir == Directions::INBOUND)
		    tmpIpPtr->addr = hdr->ip_dst.addr;
		else
			tmpIpPtr->addr = hdr->ip_src.addr;
		
		n.setLocalIp((void*)(tmpIpPtr));
		n.setIpVersion(4);
		n.setProto(hdr->ip_p);
	}
	else
	{
		const ip6_hdr * const hdr = (ip6_hdr*)ip_hdr;
		ip_size = IPv6_HDRLEN;
		ip6_addr* tmpIpPtr = new ip6_addr;

		if (dir == Directions::INBOUND)
			memcpy(tmpIpPtr, &hdr->ip6_dst, sizeof(ip6_addr));
		else
			memcpy(tmpIpPtr, &hdr->ip6_src, sizeof(ip6_addr));

		n.setLocalIp((void*)(tmpIpPtr));
		n.setIpVersion(6);
		n.setProto(hdr->ip6_nxt);
	}
	return EXIT_SUCCESS;
}


//! @todo proto can be set to 0 -> arp/rarp
inline int parsePorts(Netflow &n, Directions dir, void *hdr)
{
	switch (n.getProto())
	{
        case PROTO_TCP:
        {
            const struct tcp_hdr *tcp_hdr = (struct tcp_hdr*)hdr;
            unsigned tcp_size = tcp_hdr->th_off * 4; // number of 32 bit words in the TCP header
            if (tcp_size < 20)
            {
                log(LogLevel::WARNING, "Incorrect TCP header received.");
                return EXIT_FAILURE;
            }
            if (dir == Directions::INBOUND)
                n.setLocalPort(TOOL::ntohs(tcp_hdr->th_dport));
            else
                n.setLocalPort(TOOL::ntohs(tcp_hdr->th_sport));
            break;
        }
        case PROTO_UDP:
        case PROTO_UDPLITE: // structure of first 4 bytes is the same (srcPort and dstPort)
        {
            const struct udp_hdr *udp_hdr = (struct udp_hdr*)hdr;
            unsigned short udp_size = udp_hdr->uh_ulen; // length in bytes of the UDP header and UDP data
            if (udp_size < 8)
            {
                log(LogLevel::WARNING, "Incorrect UDP packet received with size <", udp_size, ">");
                return EXIT_FAILURE;
            }
            if (dir == Directions::INBOUND)
                n.setLocalPort(TOOL::ntohs(udp_hdr->uh_dport));
            else
                n.setLocalPort(TOOL::ntohs(udp_hdr->uh_sport));
            break;
        }
        default:
        {
            log(LogLevel::WARNING, "Unsupported transport layer protocol (", (int)n.getProto(), ")");
            return EXIT_FAILURE;
        }
	}
	return EXIT_SUCCESS;
}


void signalHandler(int signum)
{
	log(LogLevel::WARNING, "Interrupt signal (", signum, ") received.");
	if(g_pcapHandle)  pcap_breakloop(g_pcapHandle);
	shouldStop.store(signum);
}
