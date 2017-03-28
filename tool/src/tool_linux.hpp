/**
 *  @file       tool_linux.hpp
 *  @brief      Determining applications and their sockets on Linux
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:55
 *   - Edited:  28.03.2017 02:30
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


TEntry&& determineApp(Netflow *n);
unsigned int getInodeIpv4(Netflow *n);
unsigned int getInodeIpv6(Netflow *n);
void initCache(Cache *c);
