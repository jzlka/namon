/** 
 *  @file       debug.cpp
 *  @brief      Debug variables
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    16.03.2017 05:39
 *  Edited:     18.03.2017 23:52
 *  Version:    1.0.0
 */

#include "debug.hpp"



std::mutex m_debugPrint;                    //!< Mutex used to synchronize debug prints
LogLevel generalLogLevel = LogLevel::NONE;  //!< General log level

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
