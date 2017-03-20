/** 
 *  @file       pcapng_blocks.hpp
 *  @brief      Pcap-ng block structures
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    06.03.2017 13:33
 *  Edited:     20.03.2017 15:02
 *  Version:    1.0.0
 */

#pragma once

#include <cstdint>              //  uint32_t, uint16_t, uint64_t, int8_t
#include <fstream>              //  ofstream
#include <string>               //  string
#include <vector>               //  vector
#include <netinet/if_ether.h>   //  ETHER_MAX_LEN
#include "cache.hpp"            //  TEntry
#include "debug.hpp"            //  D()

//! Macro to hide compiler warning messages about unused variables
#ifdef UNUSED
/* nothing */
#elif defined(__GNUC__)
#  define UNUSED(x) __attribute__((unused)) x
#elif defined(__LCLINT__)
#  define UNUSED(x) /*@unused@*/ x
#else                /* !__GNUC__ && !__LCLINT__ */
#  define UNUSED(x) x
#endif    


using namespace std;

extern const char * g_dev;



/*!
 * @brief       Computes number of padding bytes to be inserted in order to reach multiple of x
 * @param[in]   num         Number of bytes to be padded
 * @param[in]   multiple    Padding to multiple of
 * @return      Number of padding bytes
 */
inline int computePaddingLen(int num, int multiple)
{
    if (multiple == 0)
        return num;
    int remainder = num % multiple;
    return multiple - remainder;
}


#pragma pack(push)
#pragma pack(1)

/*!
 * @class   SectionHeaderBlock
 * @brief   Section header block which has to be at the beginning of each section in the file
 */
class SectionHeaderBlock {
    UNUSED(uint32_t blockType)              = 0x0A0D0D0A;
    UNUSED(uint32_t blockTotalLength)       = sizeof(*this) - sizeof(options.shb_os.optionValue);
    UNUSED(uint32_t byteOrderMagic)         = 0x1A2B3C4D;
    UNUSED(uint16_t majorVersion)           = 1;
    UNUSED(uint16_t minorVersion)           = 0;
    UNUSED(int64_t sectionLength)           = -1;  // (not specified)
    struct {
        struct {
            UNUSED(uint16_t optionCode)     = 3;
            UNUSED(uint16_t optionLength)   = 0;        // *** will be updated in constructor
            UNUSED(char *optionValue)       = nullptr;  // *** will be updated in constructor
        } shb_os;
        struct {
            UNUSED(uint16_t optionCode)     = 4;
            UNUSED(uint16_t optionLength)   = 5;
            UNUSED(char optionValue[5])     = "tool";   //! @todo Change tool name
            UNUSED(uint8_t padding[3])      = {0};
        } shb_userappl;
        struct endOfOption {
            UNUSED(uint16_t optionCode)     = 0;
            UNUSED(uint16_t optionLength)   = 0;
        } eop;
    } options;
    UNUSED(uint32_t blockTotalLength2)      = blockTotalLength;

public:
    /*!
     * @brief       Class constructor
     * @details     Sets length of the #SectionHeaderBlock::options::shb_os option 
     *               and the block length
     * @param[in]   os  Platform and version of the OS we are capturing on
     */
    SectionHeaderBlock(string & os) 
    { 
        const int len = os.length();
        options.shb_os.optionLength = len;
        options.shb_os.optionValue = new char[len];
        os.copy(options.shb_os.optionValue, len); 

        blockTotalLength += options.shb_os.optionLength + computePaddingLen(options.shb_os.optionLength, 4);
        blockTotalLength2 = blockTotalLength;
    }
    /*!
     * @brief   Deletes allocated memory
   §  */
    ~SectionHeaderBlock()
    {
        delete [] options.shb_os.optionValue;
    }
    /*!
     * @brief       Writes whole block into the file
     * @param[in]   file    The output file
     */
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



/*!
 * @class   InterfaceDescriptionBlock
 * @brief   Block with a description of the interface used to capture network traffic
 * @details This block is mandatory if the file contains a block which refers to this device.
 *          In our case it is EnhancedPacketBlock
 */
class InterfaceDescriptionBlock {
    UNUSED(uint32_t blockType)              = 0x00000001;
    UNUSED(uint32_t blockTotalLength)       = sizeof(*this) 
                                    - sizeof(options.if_name.optionValue) 
                                    - sizeof(options.if_os.optionValue);   // *** will be updated in constructor
    UNUSED(uint16_t linkType)               = 1;        // LINKTYPE_ETHERNET(1) / LINKTYPE_IPV4(22) / LINKTYPE_IPV6(229)
    UNUSED(uint16_t reserved)               = 0;        // must be filled with 0, and ignored by file readers
    UNUSED(uint32_t snapLen)                = BUFSIZ;
    struct {
        struct {
            UNUSED(uint16_t optionCode)     = 2;
            UNUSED(uint16_t optionLength)   = strlen(g_dev);
            UNUSED(const char *optionValue) = g_dev;
        } if_name;
        struct {
            UNUSED(uint16_t optionCode)     = 9;
            UNUSED(uint16_t optionLength)   = 4;        //! @todo   Find out what value to assign
            UNUSED(char optionValue[4])     = {0};      //! @todo   Find out what value to assign
        } if_tsresol;
        struct {
            UNUSED(uint16_t optionCode)     = 12;
            UNUSED(uint16_t optionLength)   = 0;        // *** will be updated in constructor
            UNUSED(char *optionValue)       = nullptr;  // *** will be updated in constructor
        } if_os;
        struct endOfOption {
            UNUSED(uint16_t optionCode)     = 0;
            UNUSED(uint16_t optionLength)   = 0;
        } eop;
    } options;
    UNUSED(uint32_t blockTotalLength2)      = blockTotalLength;

public:
    /*!
     * @brief       Class constructor that sets options lengths and block total length
     * @todo        performed on vs performed at
     * @param[in]   os  Platform and version of the OS, the capturing was performed on
     */
    InterfaceDescriptionBlock(string & os) 
    { 
        int len = os.length();
        options.if_os.optionLength = len;
        options.if_os.optionValue = new char[len];
        os.copy(options.if_os.optionValue, len);

        blockTotalLength += options.if_name.optionLength + computePaddingLen(options.if_name.optionLength, 4) + options.if_os.optionLength + computePaddingLen(options.if_os.optionLength, 4);
        blockTotalLength2 = blockTotalLength;
    }
    /*!
     * @brief   Default destructor that deletes allocated memory used by options
     */
    ~InterfaceDescriptionBlock()
    {
        delete [] options.if_os.optionValue;
    }
    /*!
     * @brief       Writes the whole block into the file
     * @param[in]   file    The output file
     */
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



/*!
 * @class   EnhancedPacketBlock
 * @brief   Class used to store packet and information about it
 */
class EnhancedPacketBlock {
    UNUSED(uint32_t blockType)              = 0x00000006;
    UNUSED(uint32_t blockTotalLength)       = sizeof(*this)-sizeof(packetData);    // will be updated in write()
    UNUSED(uint32_t interfaceID)            = 0;
    UNUSED(uint32_t timestampHi)            = 0;
    UNUSED(uint32_t timestampLo)            = 0;
    UNUSED(uint32_t capturedPacketLength)   = 0;
    UNUSED(uint32_t originalPacketLength)   = 0;
    UNUSED(const u_char * packetData)       = nullptr;
    UNUSED(uint32_t blockTotalLength2)      = blockTotalLength;
public:
    /*!
     * @brief   Default c'tor that preallocates memory for packet
     */
    EnhancedPacketBlock() 
        { packetData = new u_char[ETHER_MAX_LEN]; }
    /*!
     * @brief   Default d'tor that deletes preallocated packet memory
     */
    ~EnhancedPacketBlock()
        { delete [] packetData; }
    /*!
     * @brief       Set method for #EnhancedPacketBlock::timestampHi 
     *               and #EnhancedPacketBlock::timestampLo
     * @param[in]   timestamp   Packet timestamp
     */
    void setTimestamp(long timestamp) { timestampLo = timestamp; timestampHi = timestamp >> 4; }
    /*!
     * @brief       Set method for #EnhancedPacketBlock::capturedPacketLength
     * @param[in]   len Captured length
     */
    void setCapturedPacketLength(uint32_t len) { capturedPacketLength = len; }
    /*!
     * @brief       Set method for #EnhancedPacketBlock::originalPacketLength
     * @param[in]   len Length of the packet as it was on the wire
     */
    void setOriginalPacketLength(uint32_t len) { originalPacketLength = len; }
    /*!
     * @brief       Set method for #EnhancedPacketBlock::packetData
     * @details     Copies a memory pointed by ptr into the preallocated space
     * @param[in]   ptr Pointer to a received packet
     */
    void setPacketData(const u_char *ptr) { memcpy((void*)packetData, ptr, capturedPacketLength); }
    /*!
     * @brief       Writes whole block into the output file
     * @param[in]   file    The output file
     */
    void write(ofstream & file)
    { 
        const char padding = 0;
        int paddingLen = computePaddingLen(capturedPacketLength, 4);
        blockTotalLength += capturedPacketLength + paddingLen;  // because of += everytime when write() is called, we have to restore default length before the function returns
        blockTotalLength2 = blockTotalLength;

        file.write(reinterpret_cast<char*>(this), sizeof(*this)-sizeof(blockTotalLength2)-sizeof(packetData));
        file.write(reinterpret_cast<const char*>(packetData), capturedPacketLength);
        while(paddingLen--)
            file.write(&padding, sizeof(padding));
        file.write(reinterpret_cast<char*>(&blockTotalLength2), sizeof(blockTotalLength2));
        blockTotalLength = sizeof(*this)-sizeof(packetData);    // restore default size of empty block
    }
};



/*!
 * @class   CustomBlock
 * @brief   Class with custom data
 */
class CustomBlock {
    UNUSED(uint32_t blockType)              = 0x40000BAD;
    UNUSED(uint32_t blockTotalLength)       = sizeof(*this) - sizeof(customData); // **** will be updated in write()
    UNUSED(uint32_t PrivateEnterpriseNumber)= 0x1234;   //! @todo PEN
    UNUSED(vector<TEntry*> customData);
    UNUSED(uint32_t blockTotalLength2)      = blockTotalLength;
public:
    /*!
     * @brief   Default c'tor
     */
    CustomBlock() 
        { }
    /*!
     * @brief       Writes the whole block into the file
     * @param[in]   file    The output file
     */
    void write(ofstream & file)
    { 
        blockTotalLength += (customData.size() * sizeof(TEntry));
        file.write(reinterpret_cast<char*>(this), blockTotalLength2 - sizeof(blockTotalLength2)); 
        
        unsigned int writtenData = 0;
        for (auto e : customData)
            writtenData += e->write(file);

        const char padding = 0;
        int paddingLen = computePaddingLen(writtenData, 4);
        while(paddingLen--)
            file.write(&padding, sizeof(padding));

        blockTotalLength2 = blockTotalLength;
        file.write(reinterpret_cast<char*>(&blockTotalLength2), sizeof(blockTotalLength2)); 
    }
};

#pragma pack(pop)

/*
 * Attributes provide the unified standard syntax for implementation-defined language extensions, 
 * such as the GNU and IBM language extensions __attribute__((...)), 
 * Microsoft extension __declspec(), etc.
 */
