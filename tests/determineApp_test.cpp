/**
 *  @file       determineApp_test.cpp
 *  @brief      Brief description
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 27.03.2017 17:03
 *   - Edited:  30.03.2017 18:00
 */

#include <iostream>         //  cout, endl
#include "tool_linux.hpp"


using namespace std;

const unsigned char     PROTO_UDP       =   0x11;
const unsigned char     PROTO_TCP       =   0x06;
const unsigned char     PROTO_UDPLITE   =   0x88;

void printHelp()
{
    cout << "Usage: ./getInode_test <localIpv4> <localPort> <protocol>" << endl;
}

void setTestingStructure(Netflow *n, unsigned int ipVer, int proto, char const *localIp, unsigned short localPort, long startTime, long endTime)
{
    n->setIpVersion(ipVer);
    n->setLocalPort(localPort);

    if (ipVer == 4)
    {
        in_addr *localIpS = new in_addr;
        inet_pton(AF_INET, localIp, localIpS);
        n->setLocalIp(localIpS);
    }
    else
    {
        in6_addr *localIpS = new in6_addr;
        inet_pton(AF_INET6, localIp, localIpS);
        n->setLocalIp(localIpS);
    }

    n->setProto(proto);
    n->setStartTime(startTime);
    n->setEndTime(endTime);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        cerr << "Argument count" << endl;
        printHelp();
        return 1;
    }

    in_addr localIp;
    if (inet_pton(AF_INET, argv[1], &localIp) == 0)
    {
        cerr << "Wrong IP" << endl;
        printHelp();
        return 1;
    }
    char *p;
    unsigned int localPort = strtoul(argv[2], &p, 10);
    if (*p)
    {
        cerr << "Wrong port" << endl;
        printHelp();
        return 1;
    }
    
    int proto = 0;
    if (string(argv[3]) == "TCP")
        proto = 6;
    else if (string(argv[3]) == "UDP")
        proto = 17;
    else
    {
        cerr << "Wrong protocol" << endl;
        printHelp();
        return 1;
    }
    Netflow n;
    n.setProto(proto);
    n.setLocalIp(&localIp);
    n.setLocalPort(localPort);
    n.setIpVersion(4);

    string filename;
    if (getSocketFile(&n, filename))
        return -1;

    ifstream socketsFile(filename);
    if (!socketsFile)
        return -1;

    int inode = getInode(&n, socketsFile);
    if (inode == -1 || inode == 0)
    {
        cerr << "Inode not found." << endl;
        return -1;
    }
    else
        cout << "Inode found! " << inode << endl;

    string appname;
    if (getApp(inode, appname))
    {
        cerr << "App with inode " << inode << " not found." << endl;
        return -1;
    }
    else
        cout << "App with inode " << inode << " is: " << appname << endl;
    return 0;
}
