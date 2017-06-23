/** 
 *  @file       namon.hpp
 *  @brief      Determining applications header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 20.03.2017 16:56
 *   - Edited:  23.06.2017 12:12
 */

#pragma once

#include "netflow.hpp"      //  Netflow
#include "cache.hpp"        //  TEntry


#define     UPDATE  0
#define     FIND    1




namespace NAMON
{


 /*!
  * @brief       Identifies application, which has opened socket which belongs to some IP, proto and port
  * @details     In case it is called with Netflow which is already in cache, but application has changed,
  *              old record is copied into #g_finalResults vector.
  *              Update mode means that instead of moving 'n' into 'e', we just update times in 'e'
  * @param[in]   n       Netflow information
  * @param[out]  e       Set application and socket inode number with netflow structure
  * @param[in]   mode    Update of expired record or inserting new record
  * @return      Value bigger than zero if there wasn't any error.
  *              -1 is returned if application or inode wasn't found - in this case #NAMON::TEntry::appName
  *              is set to empty string. If there were any Input/Output error, -2 is returned.
  */
int determineApp(Netflow *n, TEntry &e, const char mode);


}	// namespace NAMON
