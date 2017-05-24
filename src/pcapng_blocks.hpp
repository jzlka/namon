/** 
 *  @file       pcapng_blocks.hpp
 *  @brief      Pcap-ng block structures
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 06.03.2017 13:33
 *   - Edited:  24.05.2017 14:21
 */

#pragma once

#include <cstdint>              //  uint32_t, uint16_t, uint64_t, int8_t
#include <fstream>              //  ofstream
#include <string>               //  string
#include <vector>               //  vector
#include <map>                  //  map

#if defined(__linux__)
#include <cstring>              //  strlen()
#endif

#include "tcpip_headers.hpp"    //  ETHER_MAX_LEN
#include "cache.hpp"            //  TEntry
#include "debug.hpp"            //  D()



 //! Macro to hide compiler warning messages about unused variables
#ifdef UNUSED
 /* nothing */
#elif defined(__linux__)
# define UNUSED(x) x
#elif defined(__GNUC__)
#  define UNUSED(x) x __attribute__((unused))
 //#  define UNUSED(x) x [[gnu::unused]]
 //#elif defined(__LCLINT__)
#elif defined(_WIN32)
#  define UNUSED(x) /*@unused@*/ x
#else                /* !__GNUC__ && !__LCLINT__ */
#  define UNUSED(x) x
#endif 


using namespace std;

extern const char * g_dev;
extern map<string, vector<TOOL::Netflow *>> g_finalResults;




namespace TOOL
{
   

/*!
 * @brief       Computes number of padding bytes to be inserted in order to reach multiple of x
 * @param[in]   num         Number of bytes to be padded
 * @param[in]   multiple    Padding to multiple of
 * @return      Number of padding bytes
 */
inline int computePaddingLen(int num, int multiple)
{
    if (multiple == 0)
        return 0;
    int remainder = num % multiple;
    if (remainder == 0)
        return 0;
    return multiple - remainder;
}


#pragma pack(push, 1)

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
     * @details     Sets length of the #TOOL::SectionHeaderBlock::options::shb_os option 
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
            UNUSED(uint16_t optionLength)   = 1;        //! @todo   Find out what value to assign
            UNUSED(uint32_t optionValue)    = 6;        //! @todo   Find out what value to assign
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
    UNUSED(uint32_t blockTotalLength)       = sizeof(*this)-sizeof(allocatedBytes)-sizeof(packetData);    // will be updated in write()
    UNUSED(uint32_t interfaceID)            = 0;
    UNUSED(uint32_t timestampHi)            = 0;
    UNUSED(uint32_t timestampLo)            = 0;
    UNUSED(uint32_t capturedPacketLength)   = 0;
    UNUSED(uint32_t originalPacketLength)   = 0;
    UNUSED(size_t allocatedBytes)           = ETHERMTU; // not in EnhancedPacketBlock
    UNUSED(uint8_t *packetData)              = nullptr;
    UNUSED(uint32_t blockTotalLength2)      = blockTotalLength;
public:
    /*!
     * @brief   Default c'tor that preallocates memory for packet
     * @details Malloc is used instead of new because of later reallocating.
     *          http://stackoverflow.com/questions/33706528/is-it-safe-to-realloc-memory-allocated-with-new
     * @todo    Catch exception
     */
    EnhancedPacketBlock()     { packetData = (uint8_t*)malloc(ETHERMTU); if (packetData == nullptr) throw "Err"; }
    /*!
     * @brief   Default d'tor that deletes preallocated packet memory
     */
    ~EnhancedPacketBlock()    { free(packetData); }
    /*!
     * @brief       Set method for #TOOL::EnhancedPacketBlock::timestampHi 
     *               and #TOOL::EnhancedPacketBlock::timestampLo
     * @param[in]   timestamp   Packet timestamp
     */
    void setTimestamp(uint64_t timestamp) { timestampLo = timestamp & 0xffffffff; timestampHi = timestamp >> 32; }
    /*!
     * @brief       Set method for #TOOL::EnhancedPacketBlock::capturedPacketLength
     * @param[in]   len Captured length
     */
    void setCapturedPacketLength(uint32_t len) { capturedPacketLength = len; }
    /*!
     * @brief       Set method for #TOOL::EnhancedPacketBlock::originalPacketLength
     * @param[in]   len Length of the packet as it was on the wire
     */
    void setOriginalPacketLength(uint32_t len) { originalPacketLength = len; }
    /*!
     * @brief       Set method for #TOOL::EnhancedPacketBlock::packetData
     * @details     Copies a memory pointed by ptr into the preallocated space.
     *              Copy is faster than memmove
     * @todo        Catch error
     * @param[in]   ptr Pointer to a received packet
     * @param[in]   len Length of the packet
     */
    void setPacketData(const uint8_t *ptr, uint32_t len) 
    {
        if (len > allocatedBytes)
        {
            uint8_t *tmpPtr = (uint8_t*)realloc(packetData, len);
            if (tmpPtr == nullptr)
                throw "Err"; //! @todo catch and free
            packetData = tmpPtr;
            allocatedBytes = len;
        }
        // http://stackoverflow.com/questions/31898617/receiving-tcp-segments-bigger-than-mtu-with-libpcap 
        memcpy((void*)packetData, ptr, len); 
        capturedPacketLength = len; 
    }
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

        file.write(reinterpret_cast<char*>(this), sizeof(*this)-sizeof(blockTotalLength2)-sizeof(packetData)-sizeof(allocatedBytes));
        file.write(reinterpret_cast<const char*>(packetData), capturedPacketLength);
        while(paddingLen--)
            file.write(&padding, sizeof(padding));
        file.write(reinterpret_cast<char*>(&blockTotalLength2), sizeof(blockTotalLength2));
        blockTotalLength = sizeof(*this)-sizeof(allocatedBytes)-sizeof(packetData);    // restore default size of empty block
    }
};



/*!
 * @class   CustomBlock
 * @brief   Class with custom data
 */
class CustomBlock {
    UNUSED(uint32_t blockType)              = 0x40000BAD;
    UNUSED(uint32_t blockTotalLength)       = sizeof(*this); // **** will be updated in write()
    UNUSED(uint32_t PrivateEnterpriseNumber)= 0x1234;   //! @todo PEN
    /* custom data */
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
     * @todo        dat do dokumentacie, ze in_addr velkost sa moze menit (je tam long) takze musi sediet pocet netflow zaznameov a velkost tam niekam doplnit
     */
    void write(ofstream & file)
    { 
        file.write(reinterpret_cast<char*>(&blockType), sizeof(blockType));
        streamoff pos_blockTotalLength = file.tellp();
        file.write(reinterpret_cast<char*>(&blockTotalLength), sizeof(blockTotalLength));
        file.write(reinterpret_cast<char*>(&PrivateEnterpriseNumber), sizeof(PrivateEnterpriseNumber));
        
        unsigned int writtenBytes = 0;
        string appname;
        for (auto app : g_finalResults)
        {
            uint8_t size = app.first.length();
            appname = app.first;
#ifdef _WIN32 // windows appname is in quotes
/*
            if (appname[0] == '"')
            {
                appname.erase(0,1);                 // delete the first quote
                //appname.replace(appname.begin(), appname.end(),' ','\0'); // replace spaces with \0
                //appname[size - 1] = ' ';        // substitute the last '"' with terminating zero
                size--;                          // we skip the first byte
            }
            else
                log(LogLevel::ERR, "Should not happen");
*/
#else // linux sometimes does not have terminating \0 in /proc/pid/fd/cmdline
            if (app.first[size - 1] != '\0')
            {
                size++;
                appname.append(1,'\0');           // append terminating \0
            }
#endif

            file.write(reinterpret_cast<char*>(&size), sizeof(size));
            writtenBytes += sizeof(size);

            file.write(appname.c_str(), size);
            writtenBytes += size;

            //! @todo app.second->sort()
            uint32_t records = app.second.size();
            file.write(reinterpret_cast<char*>(&records), sizeof(records));
            writtenBytes += sizeof(records);
            for (auto v : app.second)
                writtenBytes += v->write(file);
        }

        const char padding = 0;
        int paddingLen = computePaddingLen(writtenBytes, 4);
        blockTotalLength += writtenBytes + paddingLen;
        while(paddingLen--)
            file.write(&padding, sizeof(padding));

        blockTotalLength2 = blockTotalLength;
        file.write(reinterpret_cast<char*>(&blockTotalLength2), sizeof(blockTotalLength2)); 

        file.seekp(pos_blockTotalLength);
        file.write(reinterpret_cast<char*>(&blockTotalLength), sizeof(blockTotalLength)); 
    }
};

#pragma pack(pop)

/*
 * Attributes provide the unified standard syntax for implementation-defined language extensions, 
 * such as the GNU and IBM language extensions __attribute__((...)), 
 * Microsoft extension __declspec(), etc.
 */


}   // namespace TOOL
