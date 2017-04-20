/** 
 *  @file       tool.hpp
 *  @brief      Determining applications header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 20.03.2017 16:56
 *   - Edited:  20.04.2017 08:20
 *  @todo       rename file
 */

#pragma once

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  TEntry


#define     UPDATE  0
#define     FIND    1




namespace TOOL
{


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


}	// namespace TOOL
