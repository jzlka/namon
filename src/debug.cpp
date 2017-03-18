/** 
 *  @file       debug.cpp
 *  @brief      Debug variables
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    16.03.2017 05:39
 *  Edited:     16.03.2017 05:47
 *  Version:    1.0.0
 */

#include "debug.hpp"



std::mutex m_debugPrint;
LogLevel generalLogLevel = LogLevel::NONE;

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
