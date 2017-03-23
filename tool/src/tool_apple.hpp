/** 
 *  @file       tool_apple.hpp
 *  @brief      Determining the applications and their sockets on macOS
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:55
 *  Edited:     22.03.2017 17:44
 *  Version:    1.0.0
 *  @todo       rename file
 */

#pragma once

#include <netinet/ip.h>     //  ip
#include "capturing.hpp"    //  Directions
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


TEntry *determineApp (Netflow *n);
void initCache(Cache *c);
//! @todo what to do with ipv6 !?
Directions getDirection(const ip * const hdr);
