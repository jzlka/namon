/**
 *  @file       udp_client.cpp
 *  @brief      Simple UDP client
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 24.04.2017 02:17
 *   - Edited:  24.04.2017 04:29
 */

#include <iostream>         // cout, end, cerr
#include <chrono>           // duration, duration_cast, milliseconds
//#include <sys/socket.h>
#include <netdb.h>          // gethostbyname   
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
    cout << "Usage: udp-client <server IP address> [port-number] <pps> <packet-size>" << endl;
    cout << "Default port is " << DEFAULT_PORT << endl;
}


void signalHandler(int signum)
{
	cerr << "Interrupt signal (" << signum << ") received.";
	shouldStop = signum;
}


int main(int argc , char *argv[])
{
    int fd;                           // an incoming socket descriptor
    unsigned short port = DEFAULT_PORT;
    unsigned long sentPackets = 0;
    unsigned int pps = 0;
    unsigned short packetSize = 0;
    
    try
    {
#ifdef _WIN32
        SetConsoleCtrlHandler((PHANDLER_ROUTINE)signalHandler, TRUE);
#else
        signal(SIGINT, signalHandler);      signal(SIGTERM, signalHandler);
        signal(SIGABRT, signalHandler);     signal(SIGSEGV, signalHandler);
#endif
        if (argc > 5)
            throw "Wrong arguments";
        else if (argc == 4)
        {
            port = atoi(argv[2]);
            pps = atoi(argv[3]);
            packetSize = atoi(argv[4]);
        }
        else if (argc == 3)
        {
            pps = atoi(argv[2]);
            packetSize = atoi(argv[3]);
        }
        else
            throw "Wrong arguments";

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
         
        if ((fd = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
            throw "Can't open socket";
        
        if (::bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) // binding with the port
            throw "Can't bind to port " + to_string(port);

        socklen_t len = sizeof(server);
        char buffer[BUFFER];
        clock_type::time_point start = clock_type::now();

        while(!shouldStop) 
        { 
            sendto(fd, buffer, packetSize, 0, (struct sockaddr *) &server, len);
            sentPackets++;
        } 

        auto end = clock_type::now();
        clock_type::duration duration = end - start;

        using std::chrono::milliseconds;
        using std::chrono::duration_cast;
        cout << "Sent packets: " << sentPackets 
        << " in " << duration_cast<milliseconds>(duration).count() << " miliseconds";
        if (sentPackets)
            cout << " ( ~" << ((double)sentPackets/duration_cast<milliseconds>(duration).count())/1000 << "pps )." << endl;
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
