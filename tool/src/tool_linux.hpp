/** 
 *  @file       tool_linux.hpp
 *  @brief      Determining applications and their sockets on Linux
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    18.02.2017 22:55
 *  Edited:     18.03.2017 23:30
 *  Version:    1.0.0
 *  @todo       rename file
 */

#pragma once

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


int determineApp (Netflow *n);
void initCache(Cache *c);
