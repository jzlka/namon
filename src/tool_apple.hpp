/**
 *  @file       tool_apple.hpp
 *  @brief      Determining applications and their sockets on macOS
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:55
 *   - Edited:  20.04.2017 08:19
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream

#include "netflow.hpp"      //  Netflow




namespace TOOL
{


/*!
 * @brief       Sets mac address of #g_dev interface into #g_devMac
 * @return      False in case of I/O error. Otherwise true is returned.
 */
int setDevMac();
/*!
 * @brief       Finds socket inode which belongs to Netflow n
 * @param[in]   n       Netflow information
 * @return      False if IP version is not supported or I/O error occured. True otherwise
 */
int getInode(Netflow *n);
/*!
 * @brief       Finds an application with opened socket inode in parameter
 * @param[in]   inode   Socket inode number
 * @param[out]  appName Found application
 * @return      False if I/O error occured. True otherwise.
 */
int getApp(const int inode, std::string &appName);


}	// namespace TOOL
