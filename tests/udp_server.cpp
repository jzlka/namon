/**
 *  @file       udp_server.cpp
 *  @brief      Simple UDP server
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 24.04.2017 02:17
 *   - Edited:  11.05.2017 03:16
 */

#include <iostream>         //  cout, end, cerr
#include <chrono>           //  duration, duration_cast, milliseconds
#include <string>			//  to_string
#include <signal.h>         //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV


#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>      // sockaddr_in, htonl()
#include <unistd.h>         // close()
#include <cstring>		// strcmp()
#elif defined(_WIN32)
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")
#endif



#define     BUFFER	        1600    // length of the receiving buffer
#define     DEFAULT_PORT    58900   // default UDP port


using namespace std;
#define     clock_type      chrono::high_resolution_clock


int shouldStop = 0;         // Variable which is set if program should stop


void printHelp()
{
    cout << "Usage: ./udp_server [port-number]" << endl;
    cout << "Default port is " << DEFAULT_PORT << endl;
}


void signalHandler(int signum)
{
	//cerr << "Interrupt signal (" << signum << ") received." << endl;
	shouldStop = signum;
}


int main(int argc, char *argv[])
{
    int fd;                           // an incoming socket descriptor
    unsigned short port = DEFAULT_PORT;
    unsigned long rcvdPackets = 0;
    
    try
    {
        signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
        signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);

        if (argc > 2)
            throw "Wrong arguments";
        else if (argc == 2 && strcmp("-h", argv[1]) == 0)
        {
            printHelp();
            return 0;
        }
        else if (argc == 2)
            port = atoi(argv[1]);
        
        struct sockaddr_in server;        // server's address structure
        server.sin_family = AF_INET;                     // set IPv4 addressing
        server.sin_addr.s_addr = htonl(INADDR_ANY);      // the server listens to any interface
        server.sin_port = htons(port);          // the server listens on this port
        
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // create the server UDP socket
            throw "Can't open socket";

        if (::bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) // binding with the port
            throw ("Can't bind to port " + to_string(port)).c_str();

        char buffer[BUFFER];
#if defined(__linux__)
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
#elif defined(_WIN32)
		DWORD timeout = 2000;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
#endif
            throw "Can't set timeout for socket";

        long packetSize = 0;
        clock_type::time_point start = clock_type::now();
        while (!shouldStop) 
        {
            packetSize += recvfrom(fd, buffer, BUFFER, 0, nullptr, 0);
            rcvdPackets++;
        }
        clock_type::time_point end = clock_type::now();
        clock_type::duration duration = end - start;
        packetSize = packetSize / rcvdPackets;

        using std::chrono::milliseconds;
        using std::chrono::duration_cast;
        long rcvdPps = rcvdPackets / (duration_cast<milliseconds>(duration).count()/1000.);
        cout << "Packet size   Rcvd packets   Time [ms]   ~pps   ~Mb/s" << endl;
        cout << packetSize << " " << rcvdPackets << " " << duration_cast<milliseconds>(duration).count() << " "
             << rcvdPps << " " << (rcvdPackets ? ((rcvdPps * packetSize) * 8 / 1000000.) : 0) << endl;
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
    catch (const char *msg)
    {
        cerr << "ERROR: " << msg << endl;
        printHelp();
        return EXIT_FAILURE;
    }
  
#if defined(__linux__)
    close(fd);
#elif defined(_WIN32)
	closesocket(fd);
#endif
    return EXIT_SUCCESS;
}
