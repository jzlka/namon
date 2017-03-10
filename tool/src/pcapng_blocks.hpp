/** 
 *  @file       pcapng_blocks.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    06.03.2017 13:33
 *  Edited:     10.03.2017 04:00
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @todo       change tool name in shb_userappl
 */

#pragma once

#include <cstdint>              //  uint32_t, uint16_t, uint64_t, int8_t
#include <fstream>              //  ofstream
#include <string>               //  string
#include <netinet/if_ether.h>   //  ETHER_MAX_LEN
#include "debug.hpp"            //  D()

using namespace std;

extern const char * g_dev;



inline int computePaddingLen(int num, int multiple)
{
    if (multiple == 0)
        return num;
    int remainder = num % multiple;
    return multiple - remainder;
}

#pragma pack(push)
#pragma pack(1)

class SectionHeaderBlock {
    uint32_t blockType              = 0x0A0D0D0A;
    uint32_t blockTotalLength       = sizeof(*this) - sizeof(options.shb_os.optionValue);
    uint32_t byteOrderMagic         = 0x1A2B3C4D;
    uint16_t majorVersion           = 1;
    uint16_t minorVersion           = 0;
    int64_t sectionLength           = -1;  // (not specified)
    struct {
        struct {
            uint16_t optionCode     = 3;
            uint16_t optionLength   = 0;        // *** will be updated in constructor
            char *optionValue       = nullptr;  // *** will be updated in constructor
        } shb_os;
        struct {
            uint16_t optionCode     = 4;
            uint16_t optionLength   = 5;
            char optionValue[5]     = "tool";   // TODO change
            uint8_t padding[3]      = {0};
        } shb_userappl;
        struct endOfOption {
            uint16_t optionCode     = 0;
            uint16_t optionLength   = 0;
        } eop;
    } options;
    uint32_t blockTotalLength2      = blockTotalLength;

public:
    SectionHeaderBlock(string & os) 
    { 
        const int len = os.length();
        options.shb_os.optionLength = len;
        options.shb_os.optionValue = new char[len];
        os.copy(options.shb_os.optionValue, len); 

        blockTotalLength += options.shb_os.optionLength + computePaddingLen(options.shb_os.optionLength, 4);
        blockTotalLength2 = blockTotalLength;
    }

    ~SectionHeaderBlock()
    {
        delete [] options.shb_os.optionValue;
    }

    void write(ofstream & file)
    { 
        char * tmpPtr = reinterpret_cast<char*>(this);
        size_t partToWrite = 4+4+4+2+2+8+2+2;
        file.write(tmpPtr, partToWrite); 
        file.write(options.shb_os.optionValue, options.shb_os.optionLength);

        int paddingLen = computePaddingLen(options.shb_os.optionLength, 4);
        const char padding = 0;
        while(paddingLen--)
            file.write(&padding, sizeof(padding));

        tmpPtr += partToWrite + sizeof(options.shb_os.optionValue);
        partToWrite = 2+2+5+3+2+2+4;
        file.write(tmpPtr, partToWrite); 
    }
};



/* There must be an Interface Description Block for each interface to which another block refers. Blocks such as an Enhanced Packet Block or an Interface Statistics Block contain an Interface ID value referring to a particular interface, and a Simple Packet Block implicitly refers to an interface with an Interface ID of 0. If the file does not contain any blocks that use an Interface ID, then the file does not need to have any IDBs.
*/
class InterfaceDescriptionBlock {
    uint32_t blockType              = 0x00000001;
    uint32_t blockTotalLength       = sizeof(*this) 
                                    - sizeof(options.if_name.optionValue) 
                                    - sizeof(options.if_os.optionValue);   // *** will be updated in constructor
    uint16_t linkType               = 1;        // LINKTYPE_ETHERNET(1) / LINKTYPE_IPV4(22) / LINKTYPE_IPV6(229)
    uint16_t reserved               = 0;        // must be filled with 0, and ignored by file readers
    uint32_t snapLen                = BUFSIZ;
    struct {
        struct {
            uint16_t optionCode     = 2;
            uint16_t optionLength   = strlen(g_dev);
            const char *optionValue = g_dev;
        } if_name;
        struct {
            uint16_t optionCode     = 9;
            uint16_t optionLength   = 4;        // TODO
            char optionValue[4]     = {0};      // TODO
        } if_tsresol;
        struct {
            uint16_t optionCode     = 12;
            uint16_t optionLength   = 0;        // *** will be updated in constructor
            char *optionValue       = nullptr;  // *** will be updated in constructor
        } if_os;
        struct endOfOption {
            uint16_t optionCode     = 0;
            uint16_t optionLength   = 0;
        } eop;
    } options;
    uint32_t blockTotalLength2      = blockTotalLength;

public:
    InterfaceDescriptionBlock(string & os) 
    { 
        int len = os.length();
        options.if_os.optionLength = len;
        options.if_os.optionValue = new char[len];
        os.copy(options.if_os.optionValue, len);

        blockTotalLength += options.if_name.optionLength + computePaddingLen(options.if_name.optionLength, 4) + options.if_os.optionLength + computePaddingLen(options.if_os.optionLength, 4);
        blockTotalLength2 = blockTotalLength;
    }

    ~InterfaceDescriptionBlock()
    {
        delete [] options.if_os.optionValue;
    }
    
    void write(ofstream & file)
    { 
        char * tmpPtr = reinterpret_cast<char*>(this);
        size_t partToWrite = 4+4+2+2+4+2+2;
        file.write(tmpPtr, partToWrite); 
        file.write(options.if_name.optionValue, options.if_name.optionLength);

        int paddingLen = computePaddingLen(options.if_name.optionLength, 4);
        const char padding = 0;
        while(paddingLen--)
            file.write(&padding, sizeof(padding));

        tmpPtr += partToWrite + sizeof(options.if_name.optionValue);
        partToWrite = 2+2+4+2+2;
        file.write(tmpPtr, partToWrite);
        file.write(options.if_os.optionValue, options.if_os.optionLength);

        paddingLen = computePaddingLen(options.if_os.optionLength, 4);
        while(paddingLen--)
            file.write(&padding, sizeof(padding));

        tmpPtr += partToWrite + sizeof(options.if_os.optionValue);
        partToWrite = 2+2+4;
        file.write(tmpPtr, partToWrite); 
    }
};



class EnhancedPacketBlock {
    uint32_t blockType              = 0x00000006;
    uint32_t blockTotalLength       = sizeof(*this)-sizeof(packetData);    // will be updated in write()
    uint32_t interfaceID            = 0;
    uint32_t timestampHi            = 0;
    uint32_t timestampLo            = 0;
    uint32_t capturedPacketLength   = 0;
    uint32_t originalPacketLength   = 0;
    const u_char * packetData       = nullptr;
    uint32_t blockTotalLength2      = blockTotalLength;
public:
    EnhancedPacketBlock() 
        { packetData = new u_char[ETHER_MAX_LEN]; }
    ~EnhancedPacketBlock()
        { delete [] packetData; }

    void setTimestamp(long timestamp) { timestampLo = timestamp; timestampHi = timestamp >> 4; }
    void setCapturedPacketLength(uint32_t len) { capturedPacketLength = len; }
    void setOriginalPacketLength(uint32_t len) { originalPacketLength = len; }
    void setPacketData(const u_char *ptr) { memcpy((void*)packetData, ptr, capturedPacketLength); }
    void write(ofstream & file)
    { 
        const char padding = 0;
        int paddingLen = computePaddingLen(capturedPacketLength, 4);
        blockTotalLength += capturedPacketLength + paddingLen;
        blockTotalLength2 = blockTotalLength;

        file.write(reinterpret_cast<char*>(this), sizeof(*this)-sizeof(blockTotalLength2)-sizeof(packetData));
        file.write(reinterpret_cast<const char*>(packetData), capturedPacketLength);
        while(paddingLen--)
            file.write(&padding, sizeof(padding));
        file.write(reinterpret_cast<char*>(&blockTotalLength2), sizeof(blockTotalLength2));
        blockTotalLength2 = blockTotalLength = sizeof(*this)-sizeof(packetData);    // restore default size of empty block
    }
};



class CustomBlock {
    uint32_t blockType              = 0x40000BAD;
    uint32_t blockTotalLength       = sizeof(*this); // TODO
    uint32_t PrivateEnterpriseNumber= 0x1234;   // TODO
    int64_t customData              = 0;        // TODO
    uint32_t blockTotalLength2      = blockTotalLength;
public:
    CustomBlock() 
        { }
    void write(ofstream & file)
        { file.write(reinterpret_cast<char*>(this),sizeof(*this)); }
};

#pragma pack(pop)
