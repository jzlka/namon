/**
 *  @file       tool_linux.cpp
 *  @brief      Determining applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 23:32
 *   - Edited:  29.03.2017 16:29
 *  @todo       rename file
 */

#include <fstream>              //  ifstream
#include <dirent.h>             //  opendir(), readdir()
#include <unistd.h>             //  getpid()
#include <cstring>              //  memset(), strchr()

#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache
#include "debug.hpp"            //  log()
#include "utils.hpp"            //  pidToInt()
#include "tool_linux.hpp"

const unsigned char PROTO_UDP       =   0x11;
const unsigned char PROTO_TCP       =   0x06;
const unsigned char PROTO_UDPLITE   =   0x88;
const unsigned char IPv4_SIZE       =   4;
const unsigned char IPv6_SIZE       =   16;
const char * const  PROCFS          =   "/proc/";

using namespace std;



int determineApp (Netflow *n, TEntry &e)
{
    n->print();
    int inode = 0;
    if (n->getIpVersion() == 4)
        inode = getInodeIpv4(n);
    else
        return -1;//! @todo implement

    if (inode == -1)
        return -1;
    if (inode == 0)
    {
        log(LogLevel::ERROR, "Socket not found for ", (int)n->getProto(), " port ", n->getLocalPort());
        return -1;
    }

    string appname;
    if (getApp(inode, appname))
        return -1;

    e.setInode(inode);
    e.setAppName(appname);
    Netflow *newN = new Netflow;
    *newN = move(*n);
    e.setNetflowPtr(newN);
    return 0;
}


int getInodeIpv4(Netflow *n)
{
    ifstream socketsFile;
    const unsigned int proto = n->getProto();

    try
    {
        if (proto == PROTO_UDP)
            socketsFile.open("/proc/net/udp");
        else if (proto == PROTO_UDPLITE)
            socketsFile.open("/proc/net/udplite");
        else if (proto == PROTO_TCP)
            socketsFile.open("/proc/net/tcp");
        else
            throw "Should not come here";
        if (!socketsFile)
            throw "Can't open /proc/net/<proto> file.";

        static streamoff pos_localIp, pos_localPort, pos_inode;
        static string dontCare;

        getline(socketsFile, dontCare); // get first line to find out length of the others
        int lineLength = dontCare.length() + 1;
        getline(socketsFile, dontCare, ':'); // get rid of the first column
        pos_localIp = socketsFile.tellg();
        pos_localIp++; // space after the first column ("sl")
        pos_localPort = pos_localIp + IPv4_SIZE*2 + 1; // local ip plus ':' delimiter
        // localPort remoteIp:remotePort st tx_queue:rx_queue tr:tm->when retrnsmt
        pos_inode = pos_localPort+3+ 1 +IPv4_SIZE*2+1+4+ 1+2+1 +8+1+8+ 1 +2+1+8 +1+8+1;

        unsigned int inode = 0;
        uint32_t foundPort = 0;
        in_addr foundIp = {0};
        unsigned short wantedPort = n->getLocalPort();
        do {
            socketsFile.seekg(pos_localPort); // move before localPort

            socketsFile >> hex >> foundPort;
            if (foundPort == wantedPort)
            {
                char c{0}, i{0};
                char parts[IPv4_SIZE] = {0};
                const unsigned char CHARS_PER_OCTET = 2;

                // compare localIp
                socketsFile.seekg(pos_localIp);

                while (socketsFile.get(c), c != ':')
                {
                    if (c >= '0' && c <= '9')
                        c -= '0';
                    else if (c >= 'A' && c <= 'F')
                        c = 10 + c - 'A'; // get from 'A' decimal 10
                    else
                        throw "Unexpected hexadecimal character in IP address in procfs";
                    // 01 23 45 67      :i                   (position)
                    // 0  1  2  3       :i / CHARS_PER_OCTET (corresponding octet)
                    // 01 00 00 7F      :c  == 127.0.0.1     (IP address char)
                    parts[i / CHARS_PER_OCTET] = parts[i/CHARS_PER_OCTET]*16 + c;
                    i++;
                }
                foundIp.s_addr |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

                // if it is not our IP address, continue
                if (static_cast<in_addr*>(n->getLocalIp())->s_addr != foundIp.s_addr
                        && foundIp.s_addr != 0) // faster than memcmp()
                    goto NEWLINE;

                socketsFile.seekg(pos_inode);
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
                    }
                    else
                        inColumn = false;
                }
                socketsFile.unget();

                socketsFile >> dec >> inode;
                break;
            }
NEWLINE:
            //! @todo for sure same length?
            pos_localIp += lineLength; // all lines are the same length
            pos_localPort += lineLength;
            pos_inode += lineLength;
        } while (getline(socketsFile, dontCare));
        return inode;
    }
    catch(char const *msg)
    {
        cerr << "ERROR: " << msg << endl;
        return -1;
    }
}

int getInodeIpv6(Netflow *n)
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


int getApp(const int inode, string &appname)
{
    DIR *procDir{nullptr}, *fdDir{nullptr};
    try
    {
        dirent *pidEntry{nullptr}, *fdEntry{nullptr};
        int pid{0}, fd{0};
        if ((procDir = opendir(PROCFS)) == nullptr)
            throw std_ex("Can't open /proc/ directory");

        // WIN: https://msdn.microsoft.com/en-us/library/ms683180(VS.85).aspx
        int myPid = ::getpid();

        while ((pidEntry = readdir(procDir)))
        {
            if (chToInt(pidEntry->d_name, pid))
                continue;
            if (myPid == pid)
                continue;

            string descriptorsDir = PROCFS + string(pidEntry->d_name) + "/fd/";
            if ((fdDir = opendir(descriptorsDir.c_str())) == nullptr)
                throw std_ex("Can't open " + descriptorsDir);

            while ((fdEntry = readdir(fdDir)))
            {
                if (chToInt(fdEntry->d_name, fd))
                    continue;

                if (fd <= 2) // stdout, stdin, stderr
                    continue;
                char buff[1024] ={0};
                string descriptor = PROCFS + string(pidEntry->d_name) + "/fd/" + string(fdEntry->d_name);
                int ll = readlink(descriptor.c_str(), buff, 1023);
                if (ll == -1)
                    log(LogLevel::ERROR, "Readlink error: " +descriptor +"\n" + string(strerror(errno)));
                if (buff[0] != 's' || buff[6] != ':') // socket:[<inode>]
                    continue;
                char *tmpPtr = strchr(&buff[7], ']');
                if (tmpPtr == nullptr)
                    throw std_ex("Right ']' not found in socket link");
                *tmpPtr = '\0';
                int foundInode {0};
                if (chToInt(&buff[8], foundInode))
                    throw "Can't convert socket inode to integer";
                if (foundInode == inode)
                {
                    ifstream appnameFile(PROCFS + string(pidEntry->d_name) + "/cmdline");
                    // arguments are delimited with '\0' so we read just first argument.
                    appnameFile >> appname;
                    closedir(fdDir);
                    goto END;
                }
            }
            closedir(fdDir);
        }
END:
        closedir(procDir);
        if (pidEntry == nullptr)
        {
            log(LogLevel::ERROR, "Application not found for inode " + to_string(inode));
            return -1;
        }
        return 0;
    }
    catch(std_ex& e) {
        cerr << e.what() << std::endl;
        if (procDir)
            closedir(procDir);
        if (fdDir)
            closedir(fdDir);
        return -1;
    }
    catch(char const *msg)
    {
        cerr << "ERROR: " << msg << endl;
        if (procDir)
            closedir(procDir);
        if (fdDir)
            closedir(fdDir);
        return -1;
    }
}
