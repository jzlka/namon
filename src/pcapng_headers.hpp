/** 
 *  @file		pcapng_headers.hpp
 *	@brief		Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *	@author		Jozef Zuzelka (xzuzel00)
 *	Mail:		xzuzel00@stud.fit.vutbr.cz
 *	Created:	06.03.2017 13:33
 *	Edited:		06.03.2017 17:21
 * 	Version:	1.0.0
 *	g++:		Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *	@todo       change tool name in shb_userappl
 */

#pragma once

#include <cstdint>          //  uint32_t, uint16_t, uint64_t, int8_t
#include <fstream>          //  ofstream
#include <string>           //  string


extern const char * dev;

class SectionHeaderBlock {
    uint32_t blockType              = 0x0A0D0D0A;
    uint32_t blockTotalLength       = sizeof(*this);
    uint32_t byteOrderMagic         = 0x1A2B3C4D;
    uint16_t majorVersion           = 1;
    uint16_t minorVersion           = 0;
    int64_t sectionLength           = -1;  // not specified
    struct {
        struct {
            uint16_t optionCode     = 3;
            uint16_t optionLength   = 64;
            char optionValue[64]    = {0};
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
    SectionHeaderBlock(std::string & os) 
    { 
            os.copy(options.shb_os.optionValue, 64); 
            if (os.length() < 64) 
                options.shb_os.optionLength = os.length(); 
    }
    void write(std::ofstream & file)
    { 
        file.write(reinterpret_cast<char*>(this),sizeof(*this)); 
    }
};



/* There must be an Interface Description Block for each interface to which another block refers. Blocks such as an Enhanced Packet Block or an Interface Statistics Block contain an Interface ID value referring to a particular interface, and a Simple Packet Block implicitly refers to an interface with an Interface ID of 0. If the file does not contain any blocks that use an Interface ID, then the file does not need to have any IDBs.
*/
class InterfaceDescriptionBlock {
    uint32_t blockType              = 0x00000001;
    uint32_t blockTotalLength       = sizeof(*this);
    uint16_t linkType               = 1; // LINKTYPE_ETHERNET(1)/LINKTYPE_IPV4(22)/LINKTYPE_IPV6(229)
    uint16_t reserved               = 0; // must be filled with 0, and ignored by file readers
    uint32_t snapLen                 = BUFSIZ; // not specified
    struct {
        struct {
            uint16_t optionCode     = 2;
            uint16_t optionLength   = 16;   // TODO
            char optionValue[16]    = {0};  // e.g. "en0"
        } if_name;
        struct {
            uint16_t optionCode     = 9;
            uint16_t optionLength   = 16;   // TODO
            char optionValue[16]    = {0};  // TODO
        } if_tsresol;
        struct {
            uint16_t optionCode     = 12;
            uint16_t optionLength   = 64;
            char optionValue[64]    = {0};  // padded to 32b, 64b-shb_userappl=41b for OS
        } if_os;
        struct endOfOption {
            uint16_t optionCode     = 0;
            uint16_t optionLength   = 0;
        } eop;
    } options;
    uint32_t blockTotalLength2      = blockTotalLength;
public:
    InterfaceDescriptionBlock(std::string & os) 
    { 
            os.copy(options.if_os.optionValue, 64); 
            if (os.length() < 64) 
                options.if_os.optionLength = os.length(); 
    }
    void write(std::ofstream & file)
    { 
        file.write(reinterpret_cast<char*>(this),sizeof(*this)); 
    }
};



class EnhancedPacketBlock {
    uint32_t blockType              = 0x00000006;
    uint32_t blockTotalLength       = 0;    // TODO
    uint32_t interfaceID            = 0;
    uint32_t timestampHi            = 0;    // TODO
    uint32_t timestampLo            = 0;    // TODO
    uint32_t capturedPacketLength   = 0;    // TODO
    uint32_t originalPacketLength   = 0;    // TODO
    int64_t packetData              = -1;  // not specified
    uint32_t blockTotalLength2      = blockTotalLength;
public:
    EnhancedPacketBlock() 
        { }
    void write(std::ofstream & file)
        { file.write(reinterpret_cast<char*>(this),sizeof(*this)); }
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
    void write(std::ofstream & file)
        { file.write(reinterpret_cast<char*>(this),sizeof(*this)); }
};
