/**
 *  @file       tool_apple.cpp
 *  @brief      Determining the applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 26.03.2017 14:40
 *   - Edited:  21.04.2017 01:02
 *  @todo       rename this file
 */

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache




namespace TOOL
{


int setDevMac()
{
    return -1;
}

int determineApp(Netflow * /*n*/, TEntry &/*e*/, const char /*mode*/)
{
    return -1;
}

int getInode(Netflow * /*n*/)
{
    return 0;
}

int getApp(const int/* inode*/, std::string &/*appname*/)
{
    return -1;
}


}
