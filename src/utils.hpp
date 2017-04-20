/**
 *  @file       utils.hpp
 *  @brief      Small useful functions header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 28.03.2017 14:09
 *   - Edited:  11.04.2017 00:10
 */

#pragma once
#include <exception>        //  exception
#include <string>           //  string
#include <cerrno>           //  errno

using std::string;




namespace TOOL
{


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


/**
 * @brief       Converts char* string to integer
 * @pre         'str' parameter must be zero terminated
 * @pre         'res' must be in decimal base
 * @param[in]   str String to convert
 * @param[out]  res The result
 * @return      Returns true on success, false otherwise
 */
int chToInt(char *str, int &res);

int inet_ntop(const int af, const void *src, char *dst, size_t size);

#include "utils.tpp"


}	// namespace TOOL
