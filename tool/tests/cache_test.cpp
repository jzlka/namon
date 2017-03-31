/**
 *  @file       cache_test.cpp
 *  @brief      Unit tests of cache implementation
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 15.03.2017 18:12
 *   - Edited:  31.03.2017 19:47
 */

#include <iostream>         //  cout, endl
#include <string>           //  string, to_string()
#include "cache.hpp"


using namespace std;

const unsigned char     PROTO_UDP       =   0x11;
const unsigned char     PROTO_TCP       =   0x06;
const unsigned char     PROTO_UDPLITE   =   0x88;
const bool              EVEN            =   true;
const unsigned short    ENTRIES         =   9;
const unsigned char     UDPLITE_PERIOD  =   3;



void setTestingStructures(int i, TEntry *e, unsigned int ipVer, const string &appName, int proto, char const *localIp, unsigned short localPort, long startTime, long endTime)
{
    e->setAppName(appName);
    e->setInode(i);

    Netflow *n = new Netflow;
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
    e->setNetflowPtr(n);
}


int main()
{
    Cache c;
    cout << "\n**** Local port level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        TEntry *tmpE = new TEntry();
        setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), PROTO_TCP, "0.0.0.0", i,1,1);
        c.insert(tmpE);
    }
    c.print();

    cout << "\n**** L4 protocol level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        if ((i&1) == EVEN)
        {
            TEntry *tmpE = new TEntry();
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), PROTO_UDP, "0.0.0.0", i,1,1);
            c.insert(tmpE);

            if (i%UDPLITE_PERIOD == 0)
            {
                TEntry *tmpE = new TEntry();
                setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), PROTO_UDPLITE, "0.0.0.0", i,1,1);
                c.insert(tmpE);
            }
        }
    }
    c.print();

    cout << "\n**** Local IP level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        if ((i&1) == EVEN)
        {
            TEntry *tmpE = new TEntry();
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), PROTO_UDP, "1.1.1.1", i,1,1);

            c.insert(tmpE);
        }
    }
    c.print();

    cout << "\n**** Difference just in the last level ****" << endl;
    {
        TEntry *tmpE = new TEntry();
        TEntry *tmpE1 = new TEntry();
        setTestingStructures(10, tmpE, 6, "x", PROTO_UDPLITE, "::1", 10,3,4);
        setTestingStructures(10, tmpE1, 6, "x", PROTO_UDPLITE, "::2", 10,4,5);
        c.insert(tmpE);
        c.insert(tmpE1);
    }
    c.print();

    cout << "\n**** Two same netflows ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        if ((i&1) == EVEN)
        {
            TEntry *tmpE = new TEntry();  //! @todo this case cause memory leak
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), PROTO_UDP, "1.1.1.1", i,2,2);

            c.insert(tmpE);
            delete tmpE;
        }
    }
    c.print();

    return 0;
}
