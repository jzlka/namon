/**
 *  @file       getApp_test.cpp
 *  @brief      Brief description
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 28.03.2017 17:08
 *   - Edited:  23.06.2017 12:16
 */

#include <iostream>         //  cout, cerr, endl
#include "namon_linux.hpp"   //  getApp()

using namespace std;



void printHelp()
{
    cout << "Usage: ./getApp_test <inode_number>" << endl;
}


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printHelp();
        return 1;
    }

    string appname;
    unsigned int inode = strtoul(argv[1], NULL, 10);
    if (getApp(inode, appname))
        cerr << "App with inode " << inode << " not found." << endl;
    else
        cout << "App with inode " << inode << " is: " << appname << endl;
}
