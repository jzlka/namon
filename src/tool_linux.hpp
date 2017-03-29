/**
 *  @file       tool_linux.hpp
 *  @brief      Determining applications and their sockets on Linux
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:55
 *   - Edited:  28.03.2017 21:47
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


int determineApp(Netflow *n, TEntry &e);
int getInodeIpv4(Netflow *n);
int getInodeIpv6(Netflow *n);
int getApp(const int inode, string &appname);
