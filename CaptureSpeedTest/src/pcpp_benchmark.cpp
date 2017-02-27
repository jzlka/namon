#include <iostream>     //  cout, cerr
#include <chrono>       //  duration, duration_cast, milliseconds
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"


using namespace pcpp;
using std::cout;
using std::endl;
using std::cerr;
using clock_type = std::chrono::high_resolution_clock;

bool shouldStop = 0;
long pkts = 0;
long pktsToRcv = 0;
const char *appName = nullptr;

void printUsage()
{
    cout << "Usage: " << appName << " -i <interface> <number of packets to capture>" << endl;
}


void handler(RawPacket* packet, PcapLiveDevice* dev, void* cookie)
{    
    if (++pkts == pktsToRcv)
	    shouldStop=1;
}


int benchmark(char *interface)
{
	PcapLiveDevice* dev;
    try
    {
        if ((dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface)) == NULL)
            throw "getDeviceByName() failed.";

        if (!dev->open(PcapLiveDevice::DeviceMode::Normal))   // in promiscuous mode by default
            throw "open() failed.";

        clock_type::time_point start = clock_type::now();
        if (!dev->startCapture(handler, NULL))
            throw "startCapture() failed.";
	    while (!shouldStop)
		    ;
        auto end = clock_type::now();
        clock_type::duration duration = end - start;

        using std::chrono::milliseconds;
        using std::chrono::duration_cast;
        cout << appName << " " << pkts << " " << duration_cast<milliseconds>(duration).count() << "ms " << endl;

        dev->stopCapture();
        dev->close();
    }
    catch(const char *msg) {
        cerr << "[pcpp] ERROR: " << msg << endl;
        if (dev != NULL) dev->close();
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
