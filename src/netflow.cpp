/** 
 *  @file       netflow.cpp
 *  @brief      Network structure source file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    15.03.2017 23:27
 *  Edited:     16.03.2017 00:41
 *  Version:    1.0.0
 */

#include "netflow.hpp"



extern const char * g_dev;


Netflow::Netflow(const char *intf) : interface(intf)
{}

Netflow::Netflow() : interface(g_dev)
{}

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

inline Directions Netflow::getDir()
{ 
    return dir; 
}

inline void Netflow::setDir(Directions d)
{ 
    dir = d; 
}

inline unsigned char Netflow::getIpVersion()
{ 
    return ipVersion; 
}

inline void Netflow::setIpVersion(unsigned char ipV)        
{ 
    ipVersion = ipV; 
}

inline void * Netflow::getSrcIp()
{ 
    return srcIp;  
}

inline void Netflow::setSrcIp(void *newIp)
{ 
    srcIp = newIp; 
}

inline void * Netflow::getDstIp()
{ 
    return dstIp;  
}

inline void Netflow::setDstIp(void *newIp)
{ 
    dstIp = newIp; 
}

inline unsigned short Netflow::getSrcPort()
{ 
    return srcPort;    
}

inline void Netflow::setSrcPort(unsigned short newPort)
{ 
    srcPort = newPort; 
}

inline unsigned short Netflow::getDstPort()
{ 
    return dstPort;    
}

inline void Netflow::setDstPort(unsigned short newPort)
{ 
    dstPort = newPort; 
}

inline unsigned char Netflow::getProto()
{ 
    return proto;    
}

inline void Netflow::setProto(unsigned char newProto)
{ 
    proto = newProto; 
}

inline const char * Netflow::getInterface()
{ 
    return interface; 
}

inline void Netflow::setInterface(char *newInt)
{ 
    interface = newInt; 
}

inline int Netflow::getStartTime()
{ 
    return startTime;    
}

inline void Netflow::setStartTime(long newTime)
{ 
    startTime = newTime; 
}

inline int Netflow::getEndTime()
{ 
    return endTime; 
}

inline void Netflow::setEndTime(long newTime)
{ 
    endTime = newTime; 
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
