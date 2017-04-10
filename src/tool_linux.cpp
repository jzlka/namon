/**
 *  @file       tool_linux.cpp
 *  @brief      Determining applications and their sockets in Linux
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 23:32
 *   - Edited:  10.04.2017 16:13
 *  @todo       rename file
 */

#include <fstream>              //  ifstream
#include <dirent.h>             //  opendir(), readdir()
#include <unistd.h>             //  getpid()
#include <cstring>              //  memset(), strchr()
#include <map>                  //  map
#include <netinet/if_ether.h>   //  ether_header

#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache, TEntry
#include "debug.hpp"            //  log()
#include "utils.hpp"            //  pidToInt()
#include "tool_linux.hpp"

using namespace std;


const unsigned char MAC_ADDR_SIZE   =   6;      //!< Size of MAC address
const unsigned char PROTO_UDP       =   0x11;   //!< UDP protocol number
const unsigned char PROTO_TCP       =   0x06;   //!< TCP protocol number
const unsigned char PROTO_UDPLITE   =   0x88;   //!< UDPLite protocol number
const unsigned char IPv4_SIZE       =   4;      //!< Size of IPv4 address in Bytes
const unsigned char IPv6_SIZE       =   16;     //!< Size of IPv6 address in Bytes
//const vector<string> L2SocketFiles = { "/proc/net/icmp", "/proc/net/igmp", "/proc/net/raw" };

extern const char * g_dev;
extern map<string, vector<Netflow *>> g_finalResults;
extern unsigned int g_notFoundApps, g_notFoundInodes;
extern mac_addr g_devMac;




int setDevMac()
{
 	// it's 2B type, so >> will read 2 hexa chars, which is 1 normal Byte
	uint16_t twoCharsInByte {0};
	const string macAddrPath = "/sys/class/net/" + string(g_dev) + "/address";
	ifstream devMacFile(macAddrPath);
	if (!devMacFile)
	    return -1;
	int i{0};
	do {
	    if (i >= MAC_ADDR_SIZE)
	        return -1;

	    devMacFile >> hex >> twoCharsInByte;
	    g_devMac.bytes[i] = twoCharsInByte;
	    i++; 
	} while (devMacFile.get() != '\n');
    return 0;
}


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


int determineApp (Netflow *n, TEntry &e, const char mode)
{
    static string filename;

    if (getSocketFile(n, filename))
        return -1;

    ifstream socketsFile;
    socketsFile.open(filename);
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
    if (mode == UPDATE)
    { 
        if (inode == e.getInode())
        { // if nothing changed, update time
            e.updateTime();
            e.getNetflowPtr()->setEndTime(n->getEndTime());
            return 0;
        }
        else if (e.getAppName() != "")
        { // save expired record to results
            Netflow *res = new Netflow;
            *res = *e.getNetflowPtr();
            g_finalResults[e.getAppName()].push_back(res);
        }
    }

    if (inode == 0)
    {
        log(LogLevel::WARNING, "Inode not found for port ", n->getLocalPort());
        g_notFoundInodes++;
    }
    else
    {
        string appName;
        if (getApp(inode, appName))
            return -1;

        e.setInode(inode);
        e.setAppName(appName);
    }


    if (mode == FIND)
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
    // in6_addr will be always bigger than in_addr so we can use it to store both IPv4 and IPv6
    static in6_addr foundIp;
    static size_t ipSize;

    const unsigned char ipVer = n->getIpVersion();
    if (ipVer == 4)
       ipSize = sizeof(in_addr);
    else if (ipVer == 6)
       ipSize = sizeof(in6_addr);
    else
    { 
        log(LogLevel::ERROR, "IP protocol ", ipVer, " is not supported."); 
        return -1; 
    }
    //memset(&foundIp, 0, sizeof(foundIp));

    try
    {
        static streamoff pos_localIp, pos_localPort, pos_inode;
        static string dummyStr;
        static int lineLength;
        static uint32_t foundPort;

        const unsigned short wantedPort = n->getLocalPort();
        unsigned int inode = 0;
#if 1
        const char IP_SIZE = (ipVer == 4) ? IPv4_SIZE : IPv6_SIZE;

        getline(socketsFile, dummyStr); // get first line to find out length of the other lines
        lineLength = dummyStr.length() + 1;
        getline(socketsFile, dummyStr, ':'); // get rid of the first column
        pos_localIp = socketsFile.tellg();
        pos_localIp++; // space after first column ("sl")
        pos_localPort = pos_localIp + IP_SIZE*2 + 1; // local ip plus ':' delimiter
        // localPort remoteIp:remotePort st tx_queue:rx_queue tr:tm->when retrnsmt
        pos_inode = pos_localPort+3+ 1 +IP_SIZE*2+1+4+ 1+2+1 +8+1+8+ 1 +2+1+8 +1+8+1;

        // cycle over remaining lines
        do {
            socketsFile.seekg(pos_localPort); // move before localPort

            socketsFile >> hex >> foundPort;
            //D(wantedPort << " vs. " << foundPort);
            if (foundPort == wantedPort)
            {
                char c{0}, i{0};
                vector<unsigned char> parts(IP_SIZE,0);
                const unsigned char CHARS_PER_OCTET = (ipVer == 4) ? 2 : 1; //! @todo implement ipv6

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
                    reinterpret_cast<in_addr*>(&foundIp)->s_addr |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
                }
                else
                {
                    throw "IPv6 is not supported yet."; //! @todo implement
                }

                // if it is our IP address
                // static variables are automatically initialized to zero unless there is an initializer
                // in6_addr is bigger so we can use it to compare for both ip versions
                //static char zeroBlock [sizeof(in6_addr)];
                if (!memcmp(n->getLocalIp(), &foundIp, ipSize)/* || !memcmp(&foundIp, zeroBlock, ipSize)*/)
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
        } while (getline(socketsFile, dummyStr));
#else
        socketsFile.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        ///
        //
        /
        string nextLine(istream&, string&& = string());

        // calling once, or when allocation cost doesn't matter
        auto line = nextLine(strm);
        
        // calling in a loop
        string line;
        for (...)
            line = nextLine(strm, std::move(line));
        ///
        //
        /
https://channel9.msdn.com/Events/GoingNative/2013/Writing-Quick-Code-in-Cpp-Quickly
        typedef std::istreambuf_iterator<char> iter;

        std::ifstream input_file("textfile.txt");
        iter file_begin(input_file);
        iter file_end;

        for (iter i = file_begin; i != file_end; ++i)
            std::clog << *i;
#endif
        return inode;
    }
    catch(char const *msg)
    {
        cerr << "ERROR: " << msg << endl;
        return -1;
    }
}


int getApp(const int inode, string &appName)
{
    DIR *procDir{nullptr}, *fdDir{nullptr};
    try
    {
        static char inodeBuff[32] ={0}; //! @todo size
        static string tmpString;
        dirent *pidEntry{nullptr}, *fdEntry{nullptr};
        int pid{0}, fd{0};
        if ((procDir = opendir("/proc/")) == nullptr)
            throw std_ex("Can't open /proc/ directory");

        // WIN: https://msdn.microsoft.com/en-us/library/ms683180(VS.85).aspx
        int myPid = ::getpid();

        while ((pidEntry = readdir(procDir)))
        {
            //if (chToInt(pidEntry->d_name, pid))
            //    continue;
            pid = atoi(pidEntry->d_name);
            if (myPid == pid || pid == 0)
                continue;

            tmpString = concatenate("/proc/", pidEntry->d_name, "/fd/");
            if ((fdDir = opendir(tmpString.c_str())) == nullptr)
                throw std_ex("Can't open " + tmpString);

            while ((fdEntry = readdir(fdDir)))
            {
                //if (chToInt(fdEntry->d_name, fd))
                //    continue;
                fd = atoi(fdEntry->d_name);

                if (fd <= 2) // stdin, stdout, stderr
                    continue;
                tmpString = concatenate("/proc/", pidEntry->d_name, "/fd/", fdEntry->d_name);
                int ll = readlink(tmpString.c_str(), inodeBuff, sizeof(inodeBuff));
                if (ll == -1)
                    log(LogLevel::ERROR, "Readlink error: " + tmpString +"\n" + string(strerror(errno)));
                if (inodeBuff[0] != 's' || inodeBuff[6] != ':') // socket:[<inode>]
                    continue;
                char *tmpPtr = strchr(&inodeBuff[7], ']');
                if (tmpPtr == nullptr)
                    throw std_ex("Right ']' not found in the socket link");
                *tmpPtr = '\0';
                int foundInode {0};
                //if (chToInt(&buff[8], foundInode))
                //    throw "Can't convert socket inode to integer";
                foundInode = atoi(&inodeBuff[8]);
                if (foundInode == inode)
                {
                    ifstream appNameFile(concatenate("/proc/", pidEntry->d_name, "/cmdline"));
                    // arguments are delimited with '\0'
                    getline(appNameFile,appName);

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
