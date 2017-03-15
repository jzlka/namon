/** 
 *  @file       tool_linux.cpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 23:32
 *  Edited:     15.03.2017 02:08
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @todo       rename file
 */

#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache
#include "tool_linux.hpp"



int determineApp (Netflow *n)
{
    (void)n;
    return 0;
}

void initCache(Cache *c)
{
    (void)c;
    return;
}
