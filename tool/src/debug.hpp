/** 
 *  @file       debug.hpp
 *  @brief      Debugging functions
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.09.2016 23:59
 *  Edited:     24.03.2017 20:58
 */

#pragma once

#include <iostream>     //  cerr, uint8_t
#include <mutex>        //  mutex

#define CLR  "\x1B[0m"  //!< Terminal normal color escape sequence
#define RED  "\x1B[31m" //!< Terminal red color escape sequence


extern std::mutex m_debugPrint;

/*! 
 * @enum    LogLevel
 * @brief   An enum representing debug prints verbosity
 */
enum class LogLevel : uint8_t
{
    NONE     = 0,   //!< Nothing is printed
    ERROR    = 1,   //!< Error messages
    WARNING  = 2,   //!< Warning messages
    INFO     = 3,   //!< Informational messages
};

extern LogLevel generalLogLevel;

//! Array of prefixes of debug messages
const char * const msgPrefix[] = { "", "[EE]", "[WW]", "[II]"};



/*!
 * @brief       Function prints array in hexadecimal
 * @param[in]   bitArray    Array to be printed
 * @param[in]   dataSize    Amount of data to be printed
 */
inline void printArray(const unsigned char *bitArray, const unsigned int dataSize)
{
    std::cerr << "Data (" << dataSize << "): ";
    for (unsigned int i=0; i != dataSize; i++)
        std::cerr << std::hex << (bitArray[i]>>4) << (bitArray[i]&0x0f) << std::dec;
    std::cerr << std::endl;
}

/*!
 * @brief       Function that prints log messages
 * @param[in]   ll  Verbosity level
 * @todo        Improve param description
 * @param[in]   args    Variadic parametes
 */
template <typename ... Ts>
void log(LogLevel ll, Ts&&... args)
{
    if (ll <= generalLogLevel)
    {
        std::lock_guard<std::mutex> guard(m_debugPrint);
        std::cerr << msgPrefix[static_cast<int>(ll)] << " ";
        //(std::cerr << ... << args) << std::endl;  // c++17
        int dummy[sizeof...(Ts)] = { (std::cout << args, 0)... };
        (void)dummy;    // disable warning about unused var
        std::cout << std::endl;
    }
}

/*!
 * @brief       Sets #generalLogLevel;
 * @param[in]   ll  #LogLevel
 */
void setLogLevel(char *ll);


#ifdef DEBUG_BUILD

/*!
 * @brief       Debug that calls #printArray function
 * @param[in]   bitArray    Array to be printed
 * @param[in]   dataSize    Size of the array
 */
#define D_ARRAY(bitArray, dataSize) printArray(bitArray, dataSize)
/*!
 * @brief   Variadic debug macro that prints everything to the standard error output
 * @note    Arguments must be delimited with <<
 */
#define D(...) \
do { \
    std::lock_guard<std::mutex> guard(m_debugPrint); \
    std::cerr << "DEBUG: " << __FILE__ << ":" << __LINE__ << ":<" << RED << __func__ <<  CLR << ">: "; \
    std::cerr << __VA_ARGS__ << std::endl; \
} while (0)

#else   //  DEBUG_BUILD

/*!
 * @brief       Debug macro which is substituted to nothing
 * @param[in]   x   Array to be printed
 * @param[in]   y   Size of the array
 */
#define D_ARRAY(x,y)    
/*!
 * @brief   Variadic debug macro which is substituted to nothing
 */
#define D(...)

#endif  // DEBUG_BUILD
