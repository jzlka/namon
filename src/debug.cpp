/** 
 *  @file       debug.cpp
 *  @brief      Debug variables
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 16.03.2017 05:39
 *   - Edited:  27.03.2017 00:15
 */

#include "debug.hpp"



std::mutex m_debugPrint;                    //!< Mutex used to synchronize debug prints
LogLevel generalLogLevel = LogLevel::ERROR; //!< General log level

void setLogLevel(char *ll)
{
    if (ll)
    {
        generalLogLevel = static_cast<LogLevel>(atoi(ll));
        if (generalLogLevel > LogLevel::INFO)
            generalLogLevel = LogLevel::INFO;
    }
    else
        generalLogLevel = LogLevel::ERROR;
}
