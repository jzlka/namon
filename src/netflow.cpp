/** 
 *  @file       netflow.cpp
 *  @brief      Netflow structure source file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    15.03.2017 23:27
 *  Edited:     16.03.2017 04:05
 *  Version:    1.0.0
 */

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
            return memcmp(static_cast<in_addr*>(srcIp), static_cast<in_addr*>(other.srcIp), sizeof(struct in_addr)) &&
                   memcmp(static_cast<in_addr*>(dstIp), static_cast<in_addr*>(other.dstIp), sizeof(struct in_addr));
        else
            return memcmp(static_cast<in6_addr*>(srcIp), static_cast<in6_addr*>(other.srcIp), sizeof(struct in6_addr)) &&
                   memcmp(static_cast<in6_addr*>(dstIp), static_cast<in6_addr*>(other.dstIp), sizeof(struct in6_addr));
    }
    return false;
}
