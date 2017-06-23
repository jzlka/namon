/**
 *  @file       namon_apple.cpp
 *  @brief      Determining the applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 26.03.2017 14:40
 *   - Edited:  23.06.2017 12:12
 */

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache




namespace NAMON
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
