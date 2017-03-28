/**
 *  @file       determineApp_test.cpp
 *  @brief      Brief description
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 27.03.2017 17:03
 *   - Edited:  28.03.2017 02:30
 */

#include <iostream>         //  cout, endl
#include "tool_linux.hpp"


using namespace std;

const unsigned char     PROTO_UDP       =   0x11;
const unsigned char     PROTO_TCP       =   0x06;
const unsigned char     PROTO_UDPLITE   =   0x88;


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

int main()
{
    Netflow n;
    unsigned short inode = 0;

    setTestingStructure(&n, 4, PROTO_TCP, "0.0.0.0", 54157, 0, 0);
    inode = getInodeIpv4(&n);
    cout << "Inode for 0.0.0.0:54157 is '" << inode << "'" << endl;

    setTestingStructure(&n, 4, PROTO_TCP, "0.0.0.0", 22, 0, 0);
    inode = getInodeIpv4(&n);
    cout << "Inode for 0.0.0.0:22 is '" << inode << "'" << endl;
}
