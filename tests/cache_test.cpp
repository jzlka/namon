/** 
 *  @file		cache_test.cpp
 *  @brief      Unit tests of cache implementation
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    15.03.2017 18:12
 *  Edited:		18.03.2017 00:25
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


void setTestingStructures(int i, TEntry *e, unsigned int ipVer, const string &appName, Directions d, int proto, char const *localIp, char const *remoteIp, unsigned short localPort, unsigned short remotePort)
{
    e->setAppName(appName);
    e->setInode(i);

    Netflow *n = new Netflow;
    n->setDir(d);
    n->setIpVersion(ipVer);

    if (n->getDir() == Directions::OUTBOUND)
    {
        n->setSrcPort(localPort);
        n->setDstPort(remotePort);
    }
    else
    {
        n->setSrcPort(remotePort);
        n->setDstPort(localPort);
    }

    if (ipVer == 4)
    {
        in_addr *srcIp = new in_addr;
        in_addr *dstIp = new in_addr;
        if (n->getDir() == Directions::OUTBOUND)
        {
            inet_pton(AF_INET, localIp, srcIp);
            inet_pton(AF_INET, remoteIp, dstIp); 
        }
        else
        {
            inet_pton(AF_INET, remoteIp, srcIp);
            inet_pton(AF_INET, localIp, dstIp); 
        }
        n->setSrcIp(srcIp);
        n->setDstIp(dstIp);
    }
    else
    {
        in6_addr *srcIp = new in6_addr;
        in6_addr *dstIp = new in6_addr;
        if (n->getDir() == Directions::OUTBOUND)
        {
            inet_pton(AF_INET6, localIp, srcIp);
            inet_pton(AF_INET6, remoteIp, dstIp); 
        }
        else
        {
            inet_pton(AF_INET6, remoteIp, srcIp);
            inet_pton(AF_INET6, localIp, dstIp); 
        }
        n->setSrcIp(srcIp);
        n->setDstIp(dstIp);
    }

    n->setProto(proto);
    
    e->setNetflowPtr(n);
}


int main()
{
    Cache c;
    cout << "\n**** Local port level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        TEntry *tmpE = new TEntry();
        setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), (Directions)(i&1), PROTO_TCP, "0.0.0.0", "0.0.0.0", i, 0);
        c.insert(tmpE);
    }
    c.print();

    cout << "\n**** L4 protocol level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        if ((i&1) == EVEN)
        {
            TEntry *tmpE = new TEntry();
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), (Directions)(i&1), PROTO_UDP, "0.0.0.0", "0.0.0.0", i, 0);
            c.insert(tmpE);
        
            if (i%UDPLITE_PERIOD == 0)
            {     
                TEntry *tmpE = new TEntry();
                setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), (Directions)(i&1), PROTO_UDPLITE, "0.0.0.0", "0.0.0.0", i, 0);
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
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), (Directions)(i&1), PROTO_UDP, "1.1.1.1", "0.0.0.0", i, 0);

            c.insert(tmpE);
        }
    }
    c.print();

    cout << "\n**** Remote IP level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        if ((i&1) == EVEN)
        {
            TEntry *tmpE = new TEntry();
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), (Directions)(i&1), PROTO_UDP, "1.1.1.1", "1.1.1.1", i, 0);
            c.insert(tmpE);
        }
    }
    c.print();

    cout << "\n**** Remote port level ****" << endl;
    for (int i=0; i<=ENTRIES; i++)
    {
        if ((i&1) == EVEN)
        {
            TEntry *tmpE = new TEntry();
            setTestingStructures(i, tmpE, 4, string(1,i%'~'+'!'), (Directions)(i&1), PROTO_UDP, "1.1.1.1", "1.1.1.1", i, 1);
            c.insert(tmpE);
        }
    }
    c.print();

    cout << "\n**** Difference just in the last level ****" << endl;
    {
        TEntry *tmpE = new TEntry();
        TEntry *tmpE1 = new TEntry();
        setTestingStructures(10, tmpE, 6, "x", (Directions)1, PROTO_UDPLITE, "::1", "::1", 10, 0);
        setTestingStructures(10, tmpE1, 6, "x", (Directions)1, PROTO_UDPLITE, "::1", "::1", 10, 1);
        c.insert(tmpE);
        c.insert(tmpE1);
    }
    c.print();

    return 0;
}
