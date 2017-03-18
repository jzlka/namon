/** 
 *  @file       tool_apple.hpp
 *  @brief      Determining the applications and their sockets on macOS
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:55
 *  Edited:     18.03.2017 23:29
 *  Version:    1.0.0
 *  @todo       rename file
 */

#pragma once

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache

class Cache;

int determineApp (Netflow *n);
void initCache(Cache *c);
