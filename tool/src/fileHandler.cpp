/** 
 *  @file		fileHandler.cpp
 *	@brief		Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *	@author		Jozef Zuzelka (xzuzel00)
 *	Mail:		xzuzel00@stud.fit.vutbr.cz
 *	Created:	06.03.2017 14:51
 *	Edited:		06.03.2017 17:22
 * 	Version:	1.0.0
 *	g++:		Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *	@bug
 *	@todo
 */



#include <fstream>                  //  fstream
#include <string>                   //  string
#include <sys/utsname.h>            //  uname() TODO -lc pri preklade
#include "debug.hpp"                //  DEBUG()
#include "pcapng_headers.hpp"       //  SectionHeaderBlock


void initOFile(std::ofstream &file)
{
    utsname u;
    uname(&u);
    std::string os = u.sysname + std::string(" ") + u.release + std::string(",") + u.version;

    SectionHeaderBlock shb(os);
    shb.write(file);
    InterfaceDescriptionBlock idb(os);
    idb.write(file);

    ///System/Library/CoreServices/SystemVersion.plist
    //sw_vers
    //uname
    //http://stackoverflow.com/questions/11072804/how-do-i-determine-the-os-version-at-runtime-in-os-x-or-ios-without-using-gesta
}

void savePacket(std::ofstream &file)
{
    (void)file;
}
