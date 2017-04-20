/**
 *  @file       tool_win.hpp
 *  @brief      Determining applications and their sockets on Windows
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 
 *   - Edited:  20.04.2017 08:20
 *  @todo       rename file
 */

#pragma once

#include <fstream>          //  ifstream
#include <string>			//	string

#include "netflow.hpp"      //  Netflow




namespace TOOL
{


/*!
 * @brief       Sets mac address of #g_dev interface into #g_devMac
 * @return      False in case of I/O error. Otherwise true is returned.
 */
int setDevMac();
/*!
 * @brief       Finds PID which belongs to Netflow n
 * @param[in]   n    Netflow information
 * @return      False if IP version is not supported or I/O error occured. True otherwise
 */
int getPid(Netflow *n);
/*!
 * @brief       Finds an application name with given PID
 * @param[in]   pid		Process Identification Number
 * @param[out]  appName Found application name and its arguments
 * @return      False if I/O error occured. True otherwise.
 */
int getApp(const int pid, std::string &appName);


//#include "tool_win.tpp"


}	// namespace TOOL
