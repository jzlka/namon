/** 
 *  @file       netflow.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:13
 *  Edited:     06.03.2017 17:45
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 */

#pragma once

#include <string>       //  string



class Netflow  // rozlisovat ipv4 a ipv6 (rozne velkosti adries)
{
    unsigned char ipVersion;
    void *srcIp = nullptr;
    void *dstIp = nullptr;
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned char proto;
    char *interface = nullptr;
    int startTime;
    int endTime;
public:
    Netflow(void *SrcIp, void *DstIp, int SrcPort, int DstPort, int Proto, int StartTime) : 
        srcIp(SrcIp), dstIp(DstIp), srcPort(SrcPort), dstPort(DstPort), proto(Proto), startTime(StartTime)
    { }
    Netflow() {}
    unsigned char getIpVersion()                { return ipVersion; }
    void setIpVersion(unsigned char ipV)        { ipVersion = ipV; }
    //void *getSrcIp()                            { return srcIp;  }
    void setSrcIp(void *newIp)                  { srcIp = newIp; }
    //void *getDstIp()                            { return dstIp;  }
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
    void setStartTime(int newTime)              { startTime = newTime; }
    //int getEndTime()                            { return endTime;    }
    void setEndTime(int newTime)                { endTime = newTime; }
};
 /* {
 *   std::ofstream file("myfile.bin", std::ios::binary);
 *     file.write(data, 100);
 *     }
 * }
 * std::ofstream("myfile.bin", std::ios::binary).write(data, 100);
 */
