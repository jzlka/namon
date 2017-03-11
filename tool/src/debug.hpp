/** 
 *  @file       debug.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.09.2016 23:59
 *  Edited:     11.03.2017 03:23
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 */

#pragma once

#include <iostream>     //  cerr, uint8_t

#define CLR  "\x1B[0m"
#define RED  "\x1B[31m"

extern std::mutex m_debugPrint;

enum class LogLevel : uint8_t
{
    INFO     = 0,
    WARNING  = 1,
    ERROR    = 2,
    NONE     = 3,
};

extern LogLevel generalLogLevel;
const char * const msgPrefix[] = { "[II]", "[WW]", "[EE]", "" };

inline void printArray(const unsigned char *bitArray, const unsigned int dataSize)
{
    std::cerr << "Data (" << dataSize << "): " ;
    for (unsigned int i=0; i != dataSize; i++)
        std::cerr << std::hex << (bitArray[i]>>4) << (bitArray[i]&0x0f);
    std::cerr << std::endl;
}



#ifdef DEBUG_BUILD


#define D_ARRAY(bitArray, dataSize) printArray(bitArray, dataSize)

#define D(...) \
    do { \
    std::lock_guard<std::mutex> guard(m_debugPrint); \
    std::cerr << "DEBUG: " << __FILE__ << ":" << __LINE__ << ":<" << RED << __func__ <<  CLR << ">: "; \
    std::cerr << __VA_ARGS__ << std::endl; \
    } while (0)

template <typename ... Ts>
void log(LogLevel ll, Ts&&... args)
{
    if (ll >= generalLogLevel)
    {
        std::lock_guard<std::mutex> guard(m_debugPrint);
        std::cerr << msgPrefix[static_cast<int>(ll)] << " ";
        (std::cerr << ... << args) << std::endl;
    }
}


#else   //  DEBUG_BUILD


#define D_ARRAY(x,y)    
#define D(...)
template <typename ... Ts>
void log(Ts&&... ) {}


#endif  // DEBUG_BUILD
