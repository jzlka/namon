/**
 *  @file       tool_bsd.hpp
 *  @brief      Determining applications and their sockets on FreeBSD
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 
 *   - Edited:  08.04.2017 13:05
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream
#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  Cache

#define     UPDATE  0
#define     FIND    1



/*!
 * @brief       Identifies application, which has opened socket which belongs to some IP, proto and port
 * @details     In case it is called with Netflow which is already in cache, but application has changed,
 *              old record is copied into #g_finalResults vector.
 *              Update mode means that instead of moving 'n' into 'e', we just update times in 'e'
 * @param[in]   n       Netflow information
 * @param[out]  e       Set application and socket inode number with netflow structure
 * @param[in]   mode    Update of expired record or inserting new record
 * @return      True if there wasn't any input/output error. 
 *              Zerro is also returned if application wasn't found - in this case #TEntry::appName 
 *              is set to empty string. If inode wasn't found either, #TEntry::inode is set to zero.
 */
int determineApp(Netflow *n, TEntry &e, const char mode);
/*!
 * @brief       Finds socket inode which belongs to Netflow n
 * @param[in]   n       Netflow information
 * @param[in]   file    Procfs file with opened sockets
 * @return      False if IP version is not supported or I/O error occured. True otherwise
 */
int getInode(Netflow *n, std::ifstream &file);
/*!
 * @brief       Finds an application with opened socket inode in parameter
 * @param[in]   inode   Socket inode number
 * @param[out]  appName Found application
 * @return      False if I/O error occured. True otherwise.
 */
int getApp(const int inode, string &appName);
