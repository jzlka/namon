/**
 *  @file       utils.hpp
 *  @brief      Small useful functions headers
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 28.03.2017 14:09
 *   - Edited:  07.04.2017 01:00
 */

#pragma once
#include <exception>        //  exception
#include <string>           //  string
#include <cerrno>           //  errno

using std::string;



/*!
 * @brief   Exception, which takes also string as parameter
 */
struct std_ex : public std::exception
{
    string msg;
public:
    std_ex(const string& m):msg("ERROR: " + m + "\n" + (errno ? string(strerror(errno)) + "\n" : ""))
      {}
    const char *what() const throw() {
        return msg.c_str();
    }
};


struct mac_addr { 
    unsigned char bytes[6]; 
};


/**
 * @brief       Converts char* string to integer
 * @pre         'str' parameter must be zero terminated
 * @pre         'res' must be in decimal base
 * @param[in]   str String to convert
 * @param[out]  res The result
 * @return      Returns true on success, false otherwise
 */
int chToInt(char *str, int &res);



