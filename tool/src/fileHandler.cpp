/** 
 *  @file       fileHandler.cpp
 *  @brief      File handler source file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    06.03.2017 14:51
 *  Edited:     22.03.2017 17:10
 *  Version:    1.0.0
 */

#include <string>                   //  string
#include <sys/utsname.h>            //  uname() TODO -lc pri preklade
#include "debug.hpp"                //  D(), log()
#include "pcapng_blocks.hpp"        //  InterfaceDescriptionBlock, SectionHeaderBlock
#include "fileHandler.hpp"



void initOFile(std::ofstream &oFile)
{
    utsname u;
    uname(&u);
    std::string os = u.sysname + std::string(" ") + u.release + std::string(",") + u.version;

    SectionHeaderBlock shb(os);
    shb.write(oFile);
    InterfaceDescriptionBlock idb(os);
    idb.write(oFile);

    log(LogLevel::INFO, "The output file has been initialized.");
    ///System/Library/CoreServices/SystemVersion.plist
    //sw_vers
    //uname
    //http://stackoverflow.com/questions/11072804/how-do-i-determine-the-os-version-at-runtime-in-os-x-or-ios-without-using-gesta
}
