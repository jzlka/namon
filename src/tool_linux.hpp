/**
 *  @file       tool_linux.hpp
 *  @brief      Determining applications and their sockets on Linux
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 22:55
 *   - Edited:  06.04.2017 18:47
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache



/*!
 * @brief       Sets mac address of #g_dev interface into #g_devMac
 * @return      False in case of I/O error. Otherwise true is returned.
 */
int setDevMac();
/*!
 * @brief       Determines right procfs file of sockets using L4 protocol and IP header version
 * @param[in]   n       Netflow class with needed information
 * @param[out]  file    Set output file
 * @return      False in case of unsupported L4 protocol or IP version. True otherwise.
 */
int getSocketFile(Netflow *n, string &file);
/*!
 * @brief       Finds out application, which has opened socket which belongs to some IP, proto and port
 * @details     In case it is called with Netflow which is already in cache, but application owner has changed,
 *              old record is copied into #g_finalResults vector.
 *              If pointer in 'n' parameter is same like Netflow pointer stored in 'e' parameter, this function
 *              is called in update mode. That means that instead of moving 'n' into 'e', we just update times in 'e'
 * @param[in]   n   Netflow information
 * @param[out]  e   Set application and socket inode number with netflow structure
 * @return      True if there wasn't any input/output error. 
 *              Zerro is also returned if application wasn't found - in this case #TEntry::appName 
 *              is set to empty string. If either inode wasn't foudn then #TEntry::inode is set to zero.
 */
int determineApp(Netflow *n, TEntry &e);
/*!
 * @brief       Finds socket inode which belongs to Netflow n
 * @param[in]   n           Netflow information
 * @param[in]   socketsFle  Procfs file with opened sockets
 * @return      False if IP version is not supported or I/O error occured. True otherwise
 */
int getInode(Netflow *n, std::ifstream &socketsFile);
/*!
 * @brief       Finds an application with opened socket inode in parameter
 * @param[in]   inode   Socket inode number
 * @param[out]  appName Found application
 * @return      False if I/O error occured. True otherwise.
 */
int getApp(const int inode, string &appName);
