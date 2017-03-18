/** 
 *  @file       netflow.cpp
 *  @brief      Netflow structure source file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    15.03.2017 23:27
 *  Edited:     18.03.2017 22:51
 *  Version:    1.0.0
 */

#include <iostream>         //  cout, endl
#include "netflow.hpp"



Netflow::~Netflow()                                  
{ 
    if (ipVersion == 4)
    {
        delete static_cast<in_addr*>(srcIp);
        delete static_cast<in_addr*>(dstIp);
    }
    else
    {
        delete static_cast<in6_addr*>(srcIp);
        delete static_cast<in6_addr*>(dstIp);
    }
}


bool Netflow::operator==(const Netflow& other) const
{
    if(srcPort == other.srcPort && dstPort == other.dstPort && proto == other.proto)
    {
        if (ipVersion == 4)
            return !memcmp(static_cast<in_addr*>(srcIp), static_cast<in_addr*>(other.srcIp), sizeof(struct in_addr)) &&
                   !memcmp(static_cast<in_addr*>(dstIp), static_cast<in_addr*>(other.dstIp), sizeof(struct in_addr));
        else
            return !memcmp(static_cast<in6_addr*>(srcIp), static_cast<in6_addr*>(other.srcIp), sizeof(struct in6_addr)) &&
                   !memcmp(static_cast<in6_addr*>(dstIp), static_cast<in6_addr*>(other.dstIp), sizeof(struct in6_addr));
    }
    return false;
}

void Netflow::print()
{
    if (ipVersion == 4)
    {
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, srcIp, str, INET_ADDRSTRLEN);
        std::cout << str << ":"  << srcPort;
        inet_ntop(AF_INET, dstIp, str, INET_ADDRSTRLEN);
        std::cout << "  " << str;
    }
    else
    {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, srcIp, str, INET6_ADDRSTRLEN);
        std::cout << str << ":"  << srcPort;
        inet_ntop(AF_INET6, dstIp, str, INET6_ADDRSTRLEN);
        std::cout << "  " << str;
    }
    std::cout << ":" << dstPort;
    std::cout << "\t";
    switch((int)proto)
    {
        case 6:     std::cout << "TCP";      break;
        case 17:    std::cout << "UDP";      break;
        case 136:   std::cout << "UDPLite";  break;
        default:    std::cout << (int)proto;
    }

    std::cout << "\tInterface: '" << interface << "'";
    std::cout << "\tTime:" << startTime << "-" << endTime << std::endl;
}
