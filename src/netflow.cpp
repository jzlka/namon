/** 
 *  @file       netflow.cpp
 *  @brief      Netflow structure source file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    15.03.2017 23:27
 *  Edited:     22.03.2017 01:29
 *  Version:    1.0.0
 */

#include <iostream>         //  cout, endl
#include <fstream>          //  ofstream
#include "netflow.hpp"



Netflow::~Netflow()                                  
{ 
    if (ipVersion == 4)
        delete static_cast<in_addr*>(localIp);
    else
        delete static_cast<in6_addr*>(localIp);
}


bool Netflow::operator==(const Netflow& other) const
{
    if(localPort == other.localPort && proto == other.proto)
    {
        if (ipVersion == 4)
            return !memcmp(static_cast<in_addr*>(localIp), static_cast<in_addr*>(other.localIp), sizeof(struct in_addr));
        else
            return !memcmp(static_cast<in6_addr*>(localIp), static_cast<in6_addr*>(other.localIp), sizeof(struct in6_addr));
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
    size = (ipVersion == 4) ? sizeof(in_addr) : sizeof(in6_addr);
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
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, localIp, str, INET_ADDRSTRLEN);
        std::cout << str;
    }
    else
    {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, localIp, str, INET6_ADDRSTRLEN);
        std::cout << str;
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
