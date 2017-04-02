/**
 *  @file       tool_linux.cpp
 *  @brief      Determining applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 23:32
 *   - Edited:  02.04.2017 00:33
 *  @todo       rename file
 */

#include <fstream>              //  ifstream
#include <dirent.h>             //  opendir(), readdir()
#include <unistd.h>             //  getpid()
#include <cstring>              //  memset(), strchr()

#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache, TEntry
#include "debug.hpp"            //  log()
#include "utils.hpp"            //  pidToInt()
#include "tool_linux.hpp"

using namespace std;


const unsigned char PROTO_UDP       =   0x11;   //!< UDP protocol number
const unsigned char PROTO_TCP       =   0x06;   //!< TCP protocol number
const unsigned char PROTO_UDPLITE   =   0x88;   //!< UDPLite protocol number
const unsigned char IPv4_SIZE       =   4;      //!< Size of IPv4 address in Bytes
const unsigned char IPv6_SIZE       =   16;     //!< Size of IPv6 address in Bytes
const char * const  PROCFS          =   "/proc/";   //!< Proc filesystem path prefix
//const vector<string> L2SocketFiles = { "/proc/net/icmp", "/proc/net/igmp", "/proc/net/raw" };

extern map<string, vector<Netflow *>> g_finalResults;
extern unsigned int g_notFoundApps, g_notFoundInodes;


int getSocketFile(Netflow *n, string &file)
{
    const unsigned int proto = n->getProto();
    const unsigned char ipVer = n->getIpVersion();

    if (proto == PROTO_UDP)
        file = "/proc/net/udp";
    else if (proto == PROTO_UDPLITE)
        file = "/proc/net/udplite";
    else if (proto == PROTO_TCP)
        file = "/proc/net/tcp";
    else
    {
        log(LogLevel::ERROR, "Unsupported L4 protocol");
        return -1;
    }
    
    if (ipVer == 6)
        file += '6';
    else if (ipVer != 4)
    {
        log(LogLevel::ERROR, "Unsupported IP protocol");
        return -1;
    }
    return 0;
}


int determineApp (Netflow *n, TEntry &e)
{
    string filename;
    if (getSocketFile(n, filename))
        return -1;

    ifstream socketsFile(filename);
    if (!socketsFile)
    {
        log(LogLevel::ERROR, "Can't open file ", filename);
        return -1;
    }

    int inode = getInode(n, socketsFile);
    if (inode == -1)
        return -1;
    // we ignore IGMP and ICMP packets so /proc/net/igmp... can be ignored
  //  if (inode == 0)
  //  {
  //      for (auto file : L2SocketFiles)
  //      {
  //          socketsFile.close();
  //          if (ipVer == 6)
  //              file += '6';
  //          socketsFile.open(file);
  //          if (!socketsFile)
  //          {
  //              log(LogLevel::ERROR, "Can't open file ", file);
  //              return -1;
  //          }
  //          
  //          inode = getInode(n, socketsFile);
  //          if (inode == -1)
  //              return -1;
  //          if (inode > 0)
  //              break;
  //      }
  //  }

    // if we are updating existing cache record
    if (n == e.getNetflowPtr())
    { 
        if (inode == e.getInode())
        { // if nothing changed, update valid time
            e.updateTime();
            return 0;
        }
        else if (e.getAppName() != "")
        { // else save expired record to results
            Netflow *res = new Netflow;
            *res = *e.getNetflowPtr();
            g_finalResults[e.getAppName()].push_back(res);
        }
    }

    string appName;
    if (inode == 0)
    {
        log(LogLevel::WARNING, "Inode not found for port " + to_string(n->getLocalPort()));
        appName = ""; //! @todo Is inserting into cache valid begavior?
        g_notFoundInodes++;
        //return -1;
    }
    else if (getApp(inode, appName))
        return -1;


    e.setInode(inode);
    e.setAppName(appName);
    if (n != e.getNetflowPtr())
    { // if we are not updating same netflow, move if from cacheBuffer
        Netflow *newN = new Netflow;
        *newN = move(*n);
        e.setNetflowPtr(newN);
    }
    else
    { // else we update expired record with a new application so just update times
        e.getNetflowPtr()->setStartTime(n->getStartTime());
        e.getNetflowPtr()->setEndTime(n->getEndTime());
    }
    return 0;
}


int getInode(Netflow *n, ifstream &socketsFile)
{
    const unsigned char ipVer = n->getIpVersion();
    void* foundIp = nullptr;
    size_t ipSize = 0;
    if (ipVer == 4)
       {  ipSize = sizeof(in_addr); foundIp = new in_addr; }
    else if (ipVer == 6)
       {  ipSize = sizeof(in6_addr); foundIp = new in6_addr; }
    else
       { log(LogLevel::ERROR, "IP protocol ", ipVer, " is not supported."); return -1; }
    memset(foundIp, 0, ipSize);

    try
    {
        static streamoff pos_localIp, pos_localPort, pos_inode;
        static string dontCare;
        static int lineLength;

        const char IP_SIZE = (ipVer == 4) ? IPv4_SIZE : IPv6_SIZE;
        const unsigned short wantedPort = n->getLocalPort();
        unsigned int inode = 0;
        uint32_t foundPort = 0;

        getline(socketsFile, dontCare); // get first line to find out length of the other lines
        lineLength = dontCare.length() + 1;
        getline(socketsFile, dontCare, ':'); // get rid of the first column
        pos_localIp = socketsFile.tellg();
        pos_localIp++; // space after first column ("sl")
        pos_localPort = pos_localIp + IP_SIZE*2 + 1; // local ip plus ':' delimiter
        // localPort remoteIp:remotePort st tx_queue:rx_queue tr:tm->when retrnsmt
        pos_inode = pos_localPort+3+ 1 +IP_SIZE*2+1+4+ 1+2+1 +8+1+8+ 1 +2+1+8 +1+8+1;

        // cycle over remaining lines
        do {
            socketsFile.seekg(pos_localPort); // move before localPort

            socketsFile >> hex >> foundPort;
            if (foundPort == wantedPort)
            {
                char c{0}, i{0};
                vector<char> parts(IP_SIZE,0);
                const unsigned char CHARS_PER_OCTET = (ipVer == 4) ? 2 : 0; //! @todo implement ipv6

                // compare localIp
                socketsFile.seekg(pos_localIp);

                if (ipVer == 4)
                {
                    while (socketsFile.get(c), c != ':' && c != 0) //! @todo why 0?
                    {
                        if (c >= '0' && c <= '9')
                            c -= '0';
                        else if (c >= 'A' && c <= 'F')
                            c = 10 + c - 'A'; // get from 'A' decimal 10
                        else
                        {
                            log(LogLevel::ERROR, "An Unexpected hexadecimal character in IP address in procfs: ", c);
                            break;
                        }
                        // 01 23 45 67      :i                   (position)
                        // 0  1  2  3       :i / CHARS_PER_OCTET (corresponding octet)
                        // 01 00 00 7F      :c  == 127.0.0.1     (IP address char)
                        parts[i / CHARS_PER_OCTET] = parts[i/CHARS_PER_OCTET]*16 + c;
                        i++;
                    }
                    static_cast<in_addr*>(foundIp)->s_addr |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
                }
                else
                {
                    throw "IPv6 is not supported yet."; //! @todo implement
                }

                // if it is our IP address
                //! @todo zero IP
                if (!memcmp(n->getLocalIp(), foundIp, ipSize)/* || foundIp.s_addr != 0*/)
                {

                    socketsFile.seekg(pos_inode);
                    // other columns (uid, timeout) have variable width
                    char column = 0;
                    bool inColumn = false;
                    while(column != 3 && socketsFile.good())
                    {
                        //! @todo getc stucked
                        //! @warning can stuck (when file is closed? I don't know yet)
                        // it gets the same char all the time (':' when it occured after signal 2 call)
                        // so column is never 3
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
                    if (!socketsFile)
                        throw "Input/Output error";
                    socketsFile.unget();

                    socketsFile >> dec >> inode;
                    break;
                }
            }
            //! @todo for sure line have same length?
            pos_localIp += lineLength; // all lines are the same length
            pos_localPort += lineLength;
            pos_inode += lineLength;
        } while (getline(socketsFile, dontCare));

        if (ipVer == 4)
            delete static_cast<in_addr*>(foundIp);
        else
            delete static_cast<in6_addr*>(foundIp);
        return inode;
    }
    catch(char const *msg)
    {
        cerr << "ERROR: " << msg << endl;
        if (ipVer == 4)
            delete static_cast<in_addr*>(foundIp);
        else
            delete static_cast<in6_addr*>(foundIp);
        return -1;
    }
}


int getApp(const int inode, string &appName)
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

                if (fd <= 2) // stdin, stdout, stderr
                    continue;
                char buff[1024] ={0}; //! @todo size
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
                   // ifstream appNameFile(PROCFS + string(pidEntry->d_name) + "/cmdline");
                   // // arguments are delimited with '\0' so we read just first argument.
                   // appNameFile >> appName;
                    char exe[512] = {0};
                    string exeLink = PROCFS + string(pidEntry->d_name) + "/exe";
                    int ll = readlink(exeLink.c_str(), exe, 511);
                    if (ll == -1)
                        log(LogLevel::ERROR, "Readlink error: " +exeLink +"\n" + string(strerror(errno)));
                    appName = exe;

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
            appName = "";
            g_notFoundApps++;
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
