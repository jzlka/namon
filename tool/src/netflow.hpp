/** 
 *  @file       netflow.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:13
 *  Edited:     15.03.2017 03:17
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 */

#pragma once

#include <string>           //  string
#include <netinet/in.h>     //  in_addr, in6_addr

enum class Directions { OUTBOUND, INBOUND };


class Netflow  // rozlisovat ipv4 a ipv6 (rozne velkosti adries)
{
    Directions dir;
    unsigned char ipVersion;
    void *srcIp = nullptr;
    void *dstIp = nullptr;
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned char proto;
    const char *interface = nullptr;
    long startTime;
    long endTime;
public:
    Netflow(const char *intf) { interface = intf; }
    Netflow() {}
    Directions getDir()                         { return dir; }
    void setDir(Directions d)                   { dir = d; }
    unsigned char getIpVersion()                { return ipVersion; }
    void setIpVersion(unsigned char ipV)        { ipVersion = ipV; }
    void *getSrcIp()                            { return srcIp;  }
    void setSrcIp(void *newIp)                  { srcIp = newIp; }
    void *getDstIp()                            { return dstIp;  }
    void setDstIp(void *newIp)                  { dstIp = newIp; }
    unsigned short getSrcPort()                 { return srcPort;    }
    void setSrcPort(unsigned short newPort)     { srcPort = newPort; }
    unsigned short getDstPort()                 { return dstPort;    }
    void setDstPort(unsigned short newPort)     { dstPort = newPort; }
    unsigned char getProto()                    { return proto;    }
    void setProto(unsigned char newProto)       { proto = newProto; }
    //char *getInterface()                        { return interface; }
    void setInterface(char *newInt)             { interface = newInt; }
    //int getStartTime()                          { return startTime;    }
    void setStartTime(long newTime)             { startTime = newTime; }
    int getEndTime()                            { return endTime;    }
    void setEndTime(long newTime)               { endTime = newTime; }

    bool operator==(const Netflow& other) const
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
};
/*
 * std::ofstream("myfile.bin", std::ios::binary).write(data, 100);
 */
