/**
 *  @file       tcp_server.cpp
 *  @brief      Simple TCP server
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 24.04.2017 06:49
 *   - Edited:  11.05.2017 03:16
 */

#include <iostream>         // cout, end, cerr
#include <chrono>           // duration, duration_cast, milliseconds
#include <string>           // to_string
#include <signal.h>             //  signal(), SIGINT, SIGTERM, SIGABRT, SIGSEGV


#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>      // sockaddr_in, htonl()
#include <unistd.h>         // close()
#include <cstring>		// strcmp()
#include <netdb.h>          // gethostbyname   
#elif defined(_WIN32)
#include <WinSock2.h>
#endif


#define     BUFFER	        1600    // length of the receiving buffer
#define     DEFAULT_PORT    58900   // default UDP port


using namespace std;
#define     clock_type      chrono::high_resolution_clock


int shouldStop = 0;         // Variable which is set if program should stop


void printHelp()
{
    cout << "Usage: ./tcp_server [port-number]" << endl;
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
        signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
        signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);

        if (argc > 2)               // read the first parameter: a port number
            throw "Wrong arguments";
        else if (argc == 2)
            port = atoi(argv[1]);
        
        struct sockaddr_in server;        // server's address structure
        struct sockaddr_in from;          // configuration of an incoming client
        int len;
        server.sin_family = AF_INET;                     // set IPv4 addressing
        server.sin_addr.s_addr = htonl(INADDR_ANY);      // the server listens to any interface
        server.sin_port = htons(port);          // the server listens on this port
        
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) // create the server TCP socket
            throw "Can't open socket";

        if (::bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) // binding with the port
            throw ("Can't bind to port " + to_string(port)).c_str();

        if (listen(fd, 1))
            throw "listen() failed";

        char buffer[BUFFER];

        int packetSize = 0;
        int sock;
        clock_type::time_point start = clock_type::now();
        while (!shouldStop) 
        {
            if((sock = accept(fd, (sockaddr *)&from, (socklen_t *)&len)) == -1)
                throw "accept() failed";

            while((packetSize = read(fd, buffer, BUFFER)) > 0 && !shouldStop)
                rcvdPackets++;

            close (sock);
        }
        clock_type::time_point end = clock_type::now();
        clock_type::duration duration = end - start;


        using std::chrono::milliseconds;
        using std::chrono::duration_cast;
        long rcvdPps = rcvdPackets / (duration_cast<milliseconds>(duration).count()/1000.);
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
  
#if defined(__linux__)
	close(fd);
#elif defined(_WIN32)
	closesocket(fd);
#endif
    return EXIT_SUCCESS;
}
