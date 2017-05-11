/**
 *  @file       tcp_client.cpp
 *  @brief      Simple TCP client
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 24.04.2017 06:44
 *   - Edited:  11.05.2017 03:16
 */

#include <iostream>         // cout, endl, cerr
#include <chrono>           // duration, duration_cast, milliseconds
#include <string>           // to_string
#include <signal.h>         //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV
#include <thread>           // this_thread::sleep_for()

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>      // sockaddr_in, htonl()
#include <unistd.h>         // close()
#include <netdb.h>          // gethostbyname   
#include <cstring>          // memset(), memcpy()
#elif defined(_WIN32)
#include <WinSock2.h>
#endif

#define     BUFFER	        1600    // length of the receiving buffer
#define     DEFAULT_PORT    58900   // default UDP port
#define     NANOSECOND      1000000000

using namespace std;
#define     clock_type      chrono::high_resolution_clock


int shouldStop = 0;         // Variable which is set if program should stop


void printHelp()
{
    cout << "Usage: tcp_client <server IP address> [port-number] <pps> <packet-size>" << endl;
    cout << "Default port is " << DEFAULT_PORT << endl;
}


void signalHandler(int signum)
{
	cerr << "Interrupt signal (" << signum << ") received." << endl;
	shouldStop = signum;
}


int main(int argc, char *argv[])
{
    int fd;                           // an incoming socket descriptor
    unsigned short port = DEFAULT_PORT;
    unsigned long sentPackets = 0;
    unsigned int pps = 0;
    unsigned short packetSize = 0;
    
    try
    {
        signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
        signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);

        if (argc > 5)
            throw "Wrong arguments";
        else if (argc == 5)
        {
            port = atoi(argv[2]);
            pps = atoi(argv[3]);
            packetSize = atoi(argv[4]);
        }
        else if (argc == 4)
        {
            pps = atoi(argv[2]);
            packetSize = atoi(argv[3]);
        }
        else
            throw "Wrong arguments";

        if (pps == 0)
            throw "Invalid pps argument";

        struct hostent *servent;
        // make DNS resolution of the first parameter using gethostbyname()
        if ((servent = gethostbyname(argv[1])) == NULL)
          throw "gethostbyname() failed";
      
        struct sockaddr_in server;        // server's address structure
        memset(&server,0,sizeof(server)); // erase the server structure
        server.sin_family = AF_INET;                   
        // copy the first parameter to the server.sin_addr structure
        memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 
        server.sin_port = htons(port);        // server port (network byte order)
         
        if ((fd = socket(AF_INET , SOCK_STREAM , 0)) == -1)   //create a client socket
            throw "Can't open socket";
        
        if (connect(fd, (sockaddr *)&server, sizeof(server)) == -1)
            throw "connect() failed";

        char buffer[BUFFER];

        long sleepTime = 0;
        unsigned int maxPps = 1000000000 / (packetSize * 8);
        if (pps < maxPps)
            sleepTime = ((double)(pps * NANOSECOND) / maxPps) / pps;
        else
            cerr << "Too high pps, maximum possible value is <" << maxPps << ">" << endl;

        const unsigned int headersSize = 18+20+8;
        const unsigned int dataSize = (packetSize <= headersSize) ? 0 : packetSize - headersSize;
        if (dataSize >= BUFFER)
            throw "Too big packet size";

        using std::chrono::nanoseconds;
        using std::chrono::duration_cast;


        clock_type::time_point start = clock_type::now();
        while(!shouldStop) 
        { 
            write(fd, buffer, dataSize);
            sentPackets++;
            this_thread::sleep_for(nanoseconds(sleepTime));
        } 
        clock_type::time_point end = clock_type::now();
        clock_type::duration duration = end - start;


        using std::chrono::milliseconds;
        long sentPps = sentPackets / (duration_cast<milliseconds>(duration).count() / 1000.);
        cout << "Sent packets: " << sentPackets 
             << " in " << duration_cast<milliseconds>(duration).count() << " miliseconds"
             << " ( ~" << sentPps << "pps | " << (sentPps * packetSize) * 8 / 1000000. << "Mb/s )." << endl;
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
