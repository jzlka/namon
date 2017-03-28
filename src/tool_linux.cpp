/**
 *  @file       tool_linux.cpp
 *  @brief      Determining applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 23:32
 *   - Edited:  28.03.2017 03:54
 *  @todo       rename file
 */

#include <fstream>              //  ifstream
#if defined(__linux__)
#include <cstring>              //  memset()
#endif

#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache
#include "debug.hpp"            //  log()
#include "tool_linux.hpp"

const unsigned char PROTO_UDP       =   0x11;
const unsigned char PROTO_TCP       =   0x06;
const unsigned char PROTO_UDPLITE   =   0x88;
const unsigned char IPv4_SIZE       =   4;
const unsigned char IPv6_SIZE       =   16;
const int powerOf16[]               =   {16, 0}; // in reverse order

using namespace std;

//! @todo   https://github.com/Distrotech/lsof/blob/master/dialects/linux/dproc.c#L457



TEntry&& determineApp (Netflow *n)
{
    unsigned int inode = 0;
    if (n->getIpVersion() == 4)
        inode = getInodeIpv4(n);
    else
        ;//! @todo implement
}

unsigned int getInodeIpv4(Netflow *n)
{
    ifstream socketsFile;
    const unsigned int proto = n->getProto();

    if (proto == PROTO_UDP)
        socketsFile.open("/proc/net/udp");
    else if (proto == PROTO_UDPLITE)
        socketsFile.open("/proc/net/udplite");
    else if (proto == PROTO_TCP)
        socketsFile.open("/proc/net/tcp");
    else
        throw "Should not come here"; //! @todo catch
    if (!socketsFile)
        throw "Err"; //! @todo catch

    streamoff pos_localIp, pos_localPort;
    string dontCare;

    getline(socketsFile, dontCare, ':');
    pos_localIp = 1;  // space after the "sl" column
    pos_localPort = pos_localIp + IPv4_SIZE*2 + 1; // plus ':' delimiter

    unsigned int inode = 0;
    uint32_t localPort = 0;
    in_addr localIp = {0};
    unsigned short wantedLocalPort = n->getLocalPort();
    do {
        pos_localIp += socketsFile.tellg(); // every cycle localIp position on the next line
        pos_localPort += socketsFile.tellg();

        socketsFile.seekg(pos_localPort); // move before localPort
        socketsFile >> hex >> localPort;
        if (localPort == wantedLocalPort)
        {
            char c{0}, i{0};
            char parts[IPv4_SIZE] = {0};
            const unsigned char CHARS_PER_OCTET = 2;

            // compare localIp
            socketsFile.seekg(pos_localIp);

            while (socketsFile.get(c), c != ':')
            {
                c -= '0';
                // 01 23 45 67      :i
                // 0  1  2  3       :i / CHARS_PER_OCTET
                // 01 00 00 7F      :c ( == 127.0.0.1)
                parts[i / CHARS_PER_OCTET] += (c * powerOf16[i&1]); // save the result to right octet
                i++;
            }
            localIp.s_addr |= (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0];
            D("Local port: " << localPort << " Local ip: " << localIp.s_addr);
            // if we found right IP address, then find inode
            if (static_cast<in_addr*>(n->getLocalIp())->s_addr == localIp.s_addr || localIp.s_addr == 0)
            {
                // localPort remoteIp:remotePort st tx_queue:rx_queue tr:tm->when retrnsmt
                socketsFile.seekg(pos_localPort+3+ 1 +IPv4_SIZE*2+1+4+ 1+2+1 +8+1+8+ 1 +2+1+8 +1+8+1);
                // other columns (uid, timeout) have variable width
                char column = 0;
                bool inColumn = false;
                while(column != 3)
                {
                    socketsFile.get(c);
                    if (c != ' ')
                    {
                        if (!inColumn)
                        {
                            column++;
                            inColumn = true;
                        }
                        cout << c << "(" << (int)column << ") ";
                    }
                    else
                        inColumn = false;
                }
                socketsFile.unget();

                socketsFile >> dec >> inode;
                break;
            }
        }
    } while (getline(socketsFile, dontCare));

    return inode;
}

unsigned int getInodeIpv6(Netflow *n)
{
    ifstream socketsFile;
    const unsigned int proto = n->getProto();

    if (proto == PROTO_UDP)
        socketsFile.open("/proc/net/udp6");
    else if (proto == PROTO_UDPLITE)
        socketsFile.open("/proc/net/udplite6");
    else if (proto == PROTO_TCP)
        socketsFile.open("/proc/net/tcp6");
    else
        throw "Should not come here"; //! @todo catch
    if (!socketsFile)
        throw "Err"; //! @todo catch

    streamoff pos_localIp, pos_localPort;
    string dontCare;

    getline(socketsFile, dontCare, ':');
    pos_localIp = 1;  // space after the "sl" column
    pos_localPort = pos_localIp + IPv6_SIZE*2 + 1; // plus ':' delimiter

    unsigned int inode = 0;
    return inode;
}

void initCache(Cache *c)
{
    (void)c;
    return;
}
