/** 
 *  @file       fileHandler.cpp
 *  @brief      File handler source file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 06.03.2017 14:51
 *   - Edited:  23.06.2017 12:01
 */

#include <string>                   //  string

#if defined(_WIN32)
#include <Windows.h>				//	GetFileVersionInfo()
#include <Strsafe.h>				//	StringCchPrintf()
#include <VersionHelpers.h>			//	IsWindows*OrGreater()
#include <Winternl.h>				//	UNICODE_STRING
#else
#include <sys/utsname.h>            //  uname()
#endif

#include "debug.hpp"                //  D(), log()
#include "pcapng_blocks.hpp"        //  InterfaceDescriptionBlock, SectionHeaderBlock
#include "fileHandler.hpp"

#if defined(_WIN32)
#pragma comment(lib, "Version.lib")	//	GetFileVersionInfoSize(), GetFileVersionInfo(), VerQueryValue()
#endif


#define		UK_ENGLISH		0x0809
#define		US_ENGLISH		0x0409
#define		UNICODE			1200




namespace NAMON
{


int initOFile(std::ofstream &oFile)
{
	std::string os;

#if defined (_WIN32)
#if 0
	int OS_LEN = GetFileVersionInfoSize("kernel32.dll", nullptr);
	if (OS_LEN == 0)
	{
		log(LogLevel::ERR, "GetFileVersionInfoSize() error");
		return -1;
	}

	char *block = new char[OS_LEN + 1];
	if (block == nullptr)
	{
		log(LogLevel::ERR, "Can't allocate memory for OS version");
		return -1;
	}
	
	if (GetFileVersionInfo("kernel32.dll", 0, OS_LEN, block) == 0)
	{
		delete[] block;
		log(LogLevel::ERR, "GetFileVersionInfo() error");
		return -1;
	}

	void *str = nullptr;
	UINT strLen = 0;
	char subBlock[50];
	
	HRESULT hr;

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	UINT cbTranslate;
	void *lpBuffer = nullptr;
	UINT dwBytes = 50;

	VerQueryValue(block,
		TEXT("\\VarFileInfo\\Translation"),
		(LPVOID*)&lpTranslate,
		&cbTranslate);

	// Read the file description for each language and code page.

	for (int i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++)
	{
		hr = StringCchPrintf(subBlock, 50,
			TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"),
			lpTranslate[i].wLanguage,
			lpTranslate[i].wCodePage);
		if (FAILED(hr))
		{
			// TODO: write error handler.
		}

		// Retrieve file description for language and code page "i". 
		VerQueryValue(block,
			subBlock,
			&lpBuffer,
			&dwBytes);
	}
	
	
	
	//if (StringCchPrintf(subBlock, sizeof(subBlock), TEXT("\\StringFileInfo\\%04x%04x\\ProductVersion"), US_ENGLISH, UNICODE))
	//{
	//	delete[] block;
	//	log(LogLevel::ERR, "Can't convert \\StringFileInfo\\lang-codepage\\string-name into char*");
	//	return -1;
	//}
	////! @todo find out how to work with VerQueryValue()
	//if (VerQueryValue(block, /*subBlock*/"\\StringFileInfo\\040904B0\\ProductVersion", &str, &strLen) == 0)
	//{
	//	delete[] block;
	//	log(LogLevel::ERR, "VarQueryValue() error");
	//	return -1;
	//}
	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms647464(v=vs.85).aspx
	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms646992(v=vs.85).aspx
	UNICODE_STRING* x = (UNICODE_STRING*)block;
#else
	os = "Unknown Windows version";
//	if (IsWindows10OrGreater())
//		os = "XPOrGreater";
//	else if (IsWindows8Point1OrGreater())
	if (IsWindows8Point1OrGreater())
		os = "Windows 8.1";
	else if (IsWindows8OrGreater())
		os = "Windows 8 or Greater";
	else if (IsWindows7SP1OrGreater())
		os = "Windows 7 SP1";
	else if (IsWindows7OrGreater())
		os = "Windows 7";
	else if (IsWindowsVistaSP2OrGreater())
		os = "Windows Vista SP2";
	else if (IsWindowsVistaSP1OrGreater())
		os = "Windows Vista SP1";
	else if (IsWindowsVistaOrGreater())
		os = "Windows Vista";
	else if (IsWindowsXPSP3OrGreater())
		os = "Windows XP SP3";
	else if (IsWindowsXPSP2OrGreater())
		os = "Windows XP SP2";
	else if (IsWindowsXPSP1OrGreater())
		os = "Windows SP1";
	else if (IsWindowsXPOrGreater())
		os = "Windows XP";

	if (IsWindowsServer())
		os += "Server";
	else
		os += "Client";
#endif // 0

#else
    utsname u;
    uname(&u);
    os = u.sysname + std::string(" ") + u.release + std::string(",") + u.version;
#endif	// _WIN32

    SectionHeaderBlock shb(os);
    shb.write(oFile);
    InterfaceDescriptionBlock idb(os);
    idb.write(oFile);

    log(LogLevel::INFO, "The output file has been initialized.");
    ///System/Library/CoreServices/SystemVersion.plist
    //sw_vers
    //uname
    //http://stackoverflow.com/questions/11072804/how-do-i-determine-the-os-version-at-runtime-in-os-x-or-ios-without-using-gesta
	return 0;
}


}	// namespace NAMON
