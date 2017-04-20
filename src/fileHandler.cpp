/** 
 *  @file       fileHandler.cpp
 *  @brief      File handler source file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 06.03.2017 14:51
 *   - Edited:  20.04.2017 08:18
 */

#include <string>                   //  string
#include <vector>					//  vector

#if defined(_WIN32)
#include <Windows.h>				//	GetFileVersionInfo()
#else
#include <sys/utsname.h>            //  uname() TODO -lc pri preklade
#endif

#include "debug.hpp"                //  D(), log()
#include "pcapng_blocks.hpp"        //  InterfaceDescriptionBlock, SectionHeaderBlock
#include "fileHandler.hpp"

#if defined(_WIN32)
#pragma comment(lib, "Version.lib")	//	GetFileVersionInfoSize(), GetFileVersionInfo(), VerQueryValue()
#endif



namespace TOOL
{


void initOFile(std::ofstream &oFile)
{
	std::string os;
#if defined (_WIN32)
	int OS_LEN = GetFileVersionInfoSize("kernel32.dll", nullptr);
	if (OS_LEN == 0)
	{
		log(LogLevel::ERR, "GetFileVersionInfoSize() error");
		throw "x";

	}
	char *buff = (char*)malloc(OS_LEN + 1);
	if (buff == nullptr)
	{
		log(LogLevel::ERR, "Can't allocate memory for OS version");
		throw "x";
	}
	memset(buff, 0, OS_LEN + 1);
	if (GetFileVersionInfo("kernel32.dll", 0, OS_LEN, buff) == 0)
	{
		log(LogLevel::ERR, "Can't get system info");
		throw "x";
	}
	LPVOID *str = nullptr;
	PUINT strLen = 0;
	if (VerQueryValue(buff, TEXT("\\StringFileInfo\\<lang><codepage>\\ProductVersion"), str, strLen) == 0)
	{
		log(LogLevel::ERR, "VarQueryValue error");
		throw "x";
	}
	os = buff;
#else
    utsname u;
    uname(&u);
    os = u.sysname + std::string(" ") + u.release + std::string(",") + u.version;
#endif

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


}	// namespace TOOL
