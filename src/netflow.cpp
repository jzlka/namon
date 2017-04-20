/** 
 *  @file       netflow.cpp
 *  @brief      Netflow structure source file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 15.03.2017 23:27
 *   - Edited:  20.04.2017 08:21
 */

#include <iostream>				//  cout, endl
#include <fstream>				//  ofstream

#if defined(__APPLE__)
#include <sys/socket.h>         // AF_INET, AF_INET6

#elif defined(__linux__)
#include <cstring>              //  memcmp()
#include <sys/socket.h>         // AF_INET, AF_INET6

#elif defined(_WIN32)
#include <winsock2.h>			//	?
//#include <ws2def.h>			//	AF_INET, AF_INET6
#endif

#include "tcpip_headers.hpp"	//	ip4_addr, ip6_addr
#include "utils.hpp"			//  inet_ntop()
#include "netflow.hpp"




namespace TOOL
{
	

Netflow::~Netflow()                                  
{ 
    if (ipVersion == 4)
        delete static_cast<ip4_addr*>(localIp);
    else
        delete static_cast<ip6_addr*>(localIp);
}


bool Netflow::operator==(const Netflow& other) const
{
    if(localPort == other.localPort && proto == other.proto)
    {
        if (ipVersion == 4)
            return !memcmp(localIp, other.localIp, IPv4_ADDRLEN);
        else
            return !memcmp(localIp, other.localIp, IPv6_ADDRLEN);
    }
    return false;
}


unsigned int Netflow::write(std::ofstream &file)
{
    unsigned int writtenBytes = 0;
    size_t size;
    size = sizeof(ipVersion);
    file.write(reinterpret_cast<char*>(&ipVersion), size);
    writtenBytes += size;

    //! @todo Can ipVersion contain other number?
    size = (ipVersion == 4) ? IPv4_ADDRLEN : IPv6_ADDRLEN;
    file.write(reinterpret_cast<char*>(localIp), size);
    writtenBytes += size;

    size = sizeof(localPort);
    file.write(reinterpret_cast<char*>(&localPort), size);
    writtenBytes += size;

    size = sizeof(proto);
    file.write(reinterpret_cast<char*>(&proto), size);
    writtenBytes += size;

    size = sizeof(startTime);
    file.write(reinterpret_cast<char*>(&startTime), size);
    file.write(reinterpret_cast<char*>(&endTime), size);
    writtenBytes += size + size;
    
    return writtenBytes;
}

void Netflow::print()
{
    if (ipVersion == 4)
    {
        char str[IPv4_ADDRSTRLEN];
        inet_ntop(AF_INET, localIp, str, IPv4_ADDRSTRLEN);
        std::cout << str;
    }
    else if (ipVersion == 6)
    {
        char str[IPv6_ADDRSTRLEN];
        inet_ntop(AF_INET6, localIp, str, IPv6_ADDRSTRLEN);
        std::cout << str;
    }
    else
    {
        std::cout << "Uninitialized/moved record or unsupported IP protocol." << std::endl;
        return;
    }

    std::cout << ":" << localPort << "\t";
    switch((int)proto)
    {
        case 6:     std::cout << "TCP";      break;
        case 17:    std::cout << "UDP";      break;
        case 136:   std::cout << "UDPLite";  break;
        default:    std::cout << (int)proto;
    }

    std::cout << "\tTime:" << startTime << "-" << endTime << std::endl;
}


}	// namespace TOOL
