/** 
 *  @file       tool_linux.hpp
 *  @brief      Determining applications and their sockets on Linux
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:55
 *   - Edited:  27.03.2017 00:15
 *  @todo       rename file
 */

#pragma once

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


int determineApp (Netflow *n);
void initCache(Cache *c);
