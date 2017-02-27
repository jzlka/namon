#include <iostream>     //  cout, cerr
#include <chrono>       //  duration, duration_cast, milliseconds
#include <pcap.h>
#include <cstring>

using namespace std;
using clock_type = chrono::high_resolution_clock;

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif


long pkts = 0;
long pktsToRcv = 0;
const char *appName = nullptr;

void printUsage()
{
    cout << "Usage: " << appName << " -i <interface> <number of packets to capture>" << endl;
}


void handler(u_char *args, const struct pcap_pkthdr *header, const u_char *bytes)
{    
    pkts++;   
}



int benchmark(char *interface)
{
    pcap_t *handle;
    try
    {
        char errbuf[PCAP_ERRBUF_SIZE];
    
        if ((handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf)) == NULL)
            throw "pcap_open_live() failed.";
    
        clock_type::time_point start = clock_type::now();
        if (pcap_loop(handle, pktsToRcv, handler, NULL) == -1)
            throw "pcap_loop() failed";
        auto end = clock_type::now();
        clock_type::duration duration = end - start;

        using std::chrono::milliseconds;
        using std::chrono::duration_cast;
        cout << appName << " " << pkts << " " << duration_cast<milliseconds>(duration).count() << "ms " << endl;

        pcap_close(handle);
    }
    catch(const char *msg) {
        cerr << "[libpcap] ERROR: " << msg << endl;
        if (handle != NULL) pcap_close(handle);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


int main(int argc, char *argv[])
{
    appName = argv[0];

    if (argc != 4 || strcmp(argv[1],"-i") != 0)
    {
        printUsage();
        return EXIT_FAILURE;
    }

    pktsToRcv = strtoul(argv[3], NULL, 10);
    return benchmark(argv[2]);
}
