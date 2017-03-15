/** 
 *  @file       tool_apple.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:55
 *  Edited:     14.03.2017 15:47
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @bug
 *  @todo       rename file
 */

#pragma once

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache

class Cache;

int determineApp (Netflow *n);
void initCache(Cache *c);
