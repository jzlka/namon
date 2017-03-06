/** 
 *  @file		debug.hpp
 *	@brief		Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *	@author		Jozef Zuzelka (xzuzel00)
 *	Mail:		xzuzel00@stud.fit.vutbr.cz
 *	Created:	26.09.2016 23:59
 *	Edited:		06.03.2017 16:59
 *	g++:		Apple LLVM version 8.0.0 (clang-800.0.42.1)
 */

#pragma once

#include <iostream>     //  cerr, uint8_t

#define CLR  "\x1B[0m"
#define RED  "\x1B[31m"

enum class DebugLevel : uint8_t
{
    ERROR    = 0,
    WARNING  = 1,
    INFO     = 2,
};

extern DebugLevel generalDebugLevel;
const char * const msgPrefix[] = { "[EE]", "[WW]", "[II]" };


#ifdef DEBUG_BUILD
template <typename ... Ts>
void DEBUG(DebugLevel dbgLevel, const char * file, const int line, const char * func, Ts&&... args)
{
    if (dbgLevel <= generalDebugLevel)
    {
        std::cerr << "DEBUG: " << file << ":" << line << ":<" << RED << func <<  CLR << ">: " << msgPrefix[static_cast<int>(dbgLevel)] << " ";
        (std::cerr << ... << args) << std::endl;
    }
}
#else	//	DEBUG_BUILD
template <typename ... Ts>
void DEBUG(Ts&&... )
{
}
#endif	// DEBUG_BUILD

