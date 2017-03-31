/**
 *  @file       tool_apple.cpp
 *  @brief      Determining the applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 26.03.2017 14:40
 *   - Edited:  31.03.2017 19:36
 *  @todo       rename this file
 */



#include <fstream>          //  ifstream
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache


int getSocketFile(Netflow * /*n*/, string &/*file*/)
{
    return -1;
}

int determineApp(Netflow * /*n*/, TEntry &/*e*/)
{
    return -1;
}

void updateCacheRecord(TEntry &/*e*/)
{
    return;
}

int getInode(Netflow * /*n*/, std::ifstream &/*file*/)
{
    return 0;
}

int getApp(const int/* inode*/, string &/*appname*/)
{
    return -1;
}
