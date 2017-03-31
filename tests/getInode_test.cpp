/**
 *  @file       getInode_test.cpp
 *  @brief      Brief description
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 29.03.2017 02:11
 *   - Edited:  30.03.2017 17:58
 */

#include <iostream>         //  cout, cerr, endl
#include "tool_linux.hpp"   //  getApp()

using namespace std;



void printHelp()
{
    cout << "Usage: ./getInode_test <localIpv4> <localPort> <protocol>" << endl;
}


int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        cerr << "Argument count" << endl;
        printHelp();
        return 1;
    }

    in_addr localIp;
    if (inet_pton(AF_INET, argv[1], &localIp) == 0)
    {
        cerr << "Wrong IP" << endl;
        printHelp();
        return 1;
    }
    char *p;
    unsigned int localPort = strtoul(argv[2], &p, 10);
    if (*p)
    {
        cerr << "Wrong port" << endl;
        printHelp();
        return 1;
    }
    
    int proto = 0;
    if (string(argv[3]) == "TCP")
        proto = 6;
    else if (string(argv[3]) == "UDP")
        proto = 17;
    else
    {
        cerr << "Wrong protocol" << endl;
        printHelp();
        return 1;
    }

    Netflow n;
    n.setProto(proto);
    n.setLocalIp(&localIp);
    n.setLocalPort(localPort);
    n.setIpVersion(4);

    string filename;
    if (getSocketFile(&n, filename))
        return -1;

    ifstream socketsFile(filename);
    if (!socketsFile)
        return -1;

    int inode = getInode(&n, socketsFile);
    if (inode == -1 || inode == 0)
        cerr << "Inode not found." << endl;
    else
        cout << "Inode found! " << inode << endl;
}
