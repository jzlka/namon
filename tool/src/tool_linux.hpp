/**
 *  @file       tool_linux.hpp
 *  @brief      Determining applications and their sockets on Linux
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:55
 *   - Edited:  30.03.2017 15:49
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


int getSocketFile(Netflow *n, string &file);
int determineApp(Netflow *n, TEntry &e);
void updateCacheRecord(TEntry &e);
int getInode(Netflow *n, std::ifstream &file);
int getApp(const int inode, string &appname);
