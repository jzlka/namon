/**
 *  @file       udp_server.cpp
 *  @brief      Simple UDP server
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 24.04.2017 02:17
 *   - Edited:  25.04.2017 23:23
 */

#include <iostream>         // cout, end, cerr
#include <chrono>           // duration, duration_cast, milliseconds
//#include <sys/socket.h>
#include <arpa/inet.h>      // sockaddr_in, htonl()
#include <unistd.h>         // close()

#if defined(__linux__)
#include <signal.h>             //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV
#elif defined(_WIN32)
#endif


#define     BUFFER	        1600    // length of the receiving buffer
#define     DEFAULT_PORT    58900   // default UDP port

using namespace std;
using clock_type = chrono::high_resolution_clock;

int shouldStop = 0;         // Variable which is set if program should stop

void printHelp()
{
    cout << "Usage: ./udp_server [port-number]" << endl;
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
    unsigned long rcvdPackets = 0;
    
    try
    {
#ifdef _WIN32
        SetConsoleCtrlHandler((PHANDLER_ROUTINE)signalHandler, TRUE);
#else
        signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
        signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);
#endif
        if (argc > 2)               // read the first parameter: a port number
            throw "Wrong arguments";
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
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            throw "Can't set timeout for socket";

        int packetSize = 0;
        clock_type::time_point start = clock_type::now();
        while (!shouldStop) 
        {
            packetSize = recvfrom(fd, buffer, BUFFER, 0, nullptr, 0);
            rcvdPackets++;
        }
        auto end = clock_type::now();
        clock_type::duration duration = end - start;

        using std::chrono::milliseconds;
        using std::chrono::duration_cast;
        long long rcvdPps = rcvdPackets / (duration_cast<milliseconds>(duration).count()/1000.);
        cout << "Received packets: " << rcvdPackets 
        << " in " << duration_cast<milliseconds>(duration).count() << " miliseconds";
        if (rcvdPackets)
            cout << " ( ~" << rcvdPps << "pps | " << (rcvdPps * packetSize) * 8 / 1000000 << "Mb/s )." << endl;
        else
            cout << "." << endl;
    }
    catch (const char *msg)
    {
        cerr << "ERROR: " << msg << endl;
        printHelp();
        return EXIT_FAILURE;
    }
  
    close(fd);
    return EXIT_SUCCESS;
}
