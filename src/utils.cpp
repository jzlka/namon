/**
 *  @file       utils.cpp
 *  @brief      Small useful functions
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 28.03.2017 14:14
 *   - Edited:  10.04.2017 23:36
 */

#include <cctype>       //  isdigit()



int chToInt(char *str, int &res)
{
    for(res = 0; *str; str++)
    {
        if (!isdigit(*str))
            return 1;
        res = res*10 + (*str - '0');
    }
    return 0;
}
