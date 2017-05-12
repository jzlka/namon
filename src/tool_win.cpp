/**
*  @file       tool_win.cpp
*  @brief      Determining the applications and their sockets on Windows
*  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
*  @date
*   - Created: 13.04.2017 00:11
*   - Edited:  20.04.2017 02:31
*  @todo       rename this file
*/


#define _WIN32_DCOM
//#include <winsock2.h>
#include <WS2tcpip.h>			//	PMIB_*6*_OWNER_PID
#include <Iphlpapi.h>			//	GetAdaptersAddresses(), GetExtended*Table()
#include <Winternl.h>			//	NtQueryInformationProcess(), PEB
#include <wbemidl.h>
#include <comdef.h>				//	bstr_t

#include "netflow.hpp"			//  Netflow
#include "tcpip_headers.hpp"	//	mac_addr
#include "cache.hpp"			//  Cache
#include "debug.hpp"			//	log()
#include "utils.hpp"			//	concatenate()
#include "tool_win.hpp"


#pragma comment(lib, "Iphlpapi.lib")	//	GetAdaptersAddresses(), GetExtended*Table()
#pragma comment(lib, "Kernel32.lib")	//	OpenProcess()
#pragma comment(lib, "wbemuuid.lib")

//https://msdn.microsoft.com/en-us/library/ms686944(v=vs.85).aspx
typedef int(__cdecl *MYPROC)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

extern const char *g_dev;
extern TOOL::mac_addr g_devMac;




namespace TOOL
{


IWbemLocator *pLoc = nullptr;
IWbemServices *pSvc = nullptr;



int setDevMac()
{
	//https://msdn.microsoft.com/en-us/library/aa365915%28VS.85%29.aspx
	PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
	DWORD retVal = 0;
	ULONG outBufLen = WORKING_BUFFER_SIZE;
	ULONG Iterations = 0;
	ULONG family = AF_UNSPEC; // both IPv4 and IPv6

	do {
		pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
		if (!pAddresses)
		{
			log(LogLevel::ERR, "Can't allocate memory for IP_ADAPTER_ADDRESSES struct");
			return -1;
		}

		retVal = GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, pAddresses, &outBufLen);
		if (retVal == ERROR_BUFFER_OVERFLOW) {
			free(pAddresses);
			pAddresses = NULL;
		}
		else {
			break;
		}

		Iterations++;
	} while (Iterations < MAX_TRIES);

	if (retVal != NO_ERROR)
	{
		log(LogLevel::ERR, "Call to GetAdaptersAddresses failed with error: ", retVal);
		free(pAddresses);
		return -1;
	}

	int ret = 0;

	for (PIP_ADAPTER_ADDRESSES pos = pAddresses; pos; pos = pos->Next)
	{
		if (strcmp(pos->AdapterName, strchr(g_dev, '{')))
			continue;
		if (pos->PhysicalAddressLength != 0)
		{
			for (int i = 0; i < (int)pos->PhysicalAddressLength; i++)
				g_devMac.bytes[i] = pos->PhysicalAddress[i];
			ret = 0;
		}
		else
		{
			std::cout << "No ethernet address!";
			ret = -1;
		}
		break;
	}

	free(pAddresses);
	return ret;
}

int getPid(Netflow *n)
{
	DWORD tableSize = 0;
	uint16_t wantedPort = ntohs(n->getLocalPort());
	static int pid = 0;
	// static variables are automatically initialized to zero unless there is an initializer
	// ip6_addr is bigger so we can use it to compare for both ip versions
	// if it is our IP address or broadcast
	static char zeroBlock[sizeof(ip6_addr)];

	//! @todo convert to template function
	if (n->getIpVersion() == 4)
	{
		if (n->getProto() == PROTO_TCP)
		{
			GetExtendedTcpTable(nullptr, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
			PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID) new char[tableSize];
			if (GetExtendedTcpTable(table, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
			{
				log(LogLevel::ERR, "Unable to get IPv4 TCP table");
				delete table;
				return -2;
			}
			for (int i = 0; i < table->dwNumEntries; i++)
			{
				const MIB_TCPROW_OWNER_PID &row = table->table[i];
				//D(row.dwLocalPort << " vs." << wantedPort);
				if (row.dwLocalPort == wantedPort
					&& (row.dwLocalAddr == (*(in_addr*)n->getLocalIp()).S_un.S_addr || row.dwLocalAddr == 0))
				{
					pid = row.dwOwningPid;
					delete table;
					return pid;
				}
			}
			delete table;
			log(LogLevel::WARNING, "PID not found for port <", n->getLocalPort(), "> (IPv4)");
			return -1;
		}
		else if (n->getProto() == PROTO_UDP)
		{
			GetExtendedUdpTable(nullptr, &tableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
			PMIB_UDPTABLE_OWNER_PID table = (PMIB_UDPTABLE_OWNER_PID) new char[tableSize];
			if (GetExtendedUdpTable(table, &tableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
			{
				log(LogLevel::ERR, "Unable to get IPv4 UDP table");
				delete table;
				return -2;
			}
			for (int i = 0; i < table->dwNumEntries; i++)
			{
				const MIB_UDPROW_OWNER_PID &row = table->table[i];
				//D(row.dwLocalPort << " vs." << wantedPort);
				if (row.dwLocalPort == wantedPort
					&& (row.dwLocalAddr == (*(in_addr*)n->getLocalIp()).S_un.S_addr || row.dwLocalAddr == 0))
				{
					pid = row.dwOwningPid;
					delete table;
					return pid;
				}
			}
			delete table;
			log(LogLevel::WARNING, "PID not found for port <", n->getLocalPort(), "> (IPv4)");
			return -1;
		}
		log(LogLevel::WARNING, "Unsupported IPv4 transport layer protocol in getPid(). (", n->getProto(), ")");
		return -1;
	}
	else if (n->getIpVersion() == 6)
	{
		if (n->getProto() == PROTO_TCP)
		{
			GetExtendedTcpTable(nullptr, &tableSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
			PMIB_TCP6TABLE_OWNER_PID table = (PMIB_TCP6TABLE_OWNER_PID) new char[tableSize];
			if (GetExtendedTcpTable(table, &tableSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
			{
				log(LogLevel::ERR, "Unable to get IPv6 TCP table");
				delete table;
				return -2;
			}
			for (int i = 0; i < table->dwNumEntries; i++)
			{
				const MIB_TCP6ROW_OWNER_PID &row = table->table[i];
				//D(row.dwLocalPort << " vs." << wantedPort);
				if (row.dwLocalPort == wantedPort
					&& (!memcmp(row.ucLocalAddr, n->getLocalIp(), IPv6_ADDRLEN) || !memcmp(row.ucLocalAddr, zeroBlock, IPv6_ADDRLEN)))
				{
					pid = row.dwOwningPid;
					delete table;
					return pid;
				}
			}
			delete table;
			log(LogLevel::ERR, "PID not found for port <", n->getLocalPort(), "> (IPv6)");
			return -1;
		}
		else if (n->getProto() == PROTO_UDP)
		{
			HRESULT hr = GetExtendedUdpTable(nullptr, &tableSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
			PMIB_UDP6TABLE_OWNER_PID table = (PMIB_UDP6TABLE_OWNER_PID) new char[tableSize];
			hr = GetExtendedUdpTable(table, &tableSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
			if (hr != NO_ERROR)
			{
				log(LogLevel::ERR, "Unable to get IPv6 UDP table");
				delete table;
				return -2;
			}
			for (int i = 0; i < table->dwNumEntries; i++)
			{
				const MIB_UDP6ROW_OWNER_PID &row = table->table[i];
				//D(row.dwLocalPort << " vs." << wantedPort);
				if (row.dwLocalPort == wantedPort
					&& (!memcmp(row.ucLocalAddr, n->getLocalIp(), IPv6_ADDRLEN) || !memcmp(row.ucLocalAddr, zeroBlock, IPv6_ADDRLEN)))
				{
					pid = row.dwOwningPid;
					delete table;
					return pid;
				}
			}
			delete table;
			log(LogLevel::ERR, "PID not found for port <", n->getLocalPort(), "> (IPv6)");
			return -1;
		}
		log(LogLevel::WARNING, "Unsupported IPv6 transport layer protocol in getPid(). (", n->getProto(), ")");
		return -2;
	}
	log(LogLevel::WARNING, "Unsupported IP version in getPid(). (", n->getIpVersion(), ")");
	return -2;
}


int connectToWmi()
{
	try
	{
		//https://msdn.microsoft.com/en-us/library/aa390421(v=vs.85).aspx
		HRESULT hr;

		// Step 1: --------------------------------------------------
		// Initialize COM. ------------------------------------------

		hr = CoInitializeEx(0, COINIT_MULTITHREADED);
		if (FAILED(hr))
			throw "Failed to initialize COM library.";

		// Step 2: --------------------------------------------------
		// Set general COM security levels --------------------------

		hr = CoInitializeSecurity(
			NULL,
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
			RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities 
			NULL                         // Reserved
		);
		if (FAILED(hr))
		{
			CoUninitialize();
			throw "Failed to initialize security.";
		}

		// Step 3: ---------------------------------------------------
		// Obtain the initial locator to WMI -------------------------

		// Initialize the IWbemLocator interface throuwgh a cal to CoCreateInstance
		hr = CoCreateInstance(
			CLSID_WbemLocator, 
			0,	
			CLSCTX_INPROC_SERVER, 
			IID_IWbemLocator, 
			(LPVOID *)&pLoc);
		if (FAILED(hr))
		{
			CoUninitialize();
			throw "Failed to create IWbemLocator object.";
		}

		// Step 4: -----------------------------------------------------
		// Connect to WMI through the IWbemLocator::ConnectServer method

		// Connect to the root\cimv2 namespace with
		// the current user and obtain pointer pSvc
		// to make IWbemServices calls.
		hr = pLoc->ConnectServer(
			BSTR(L"ROOT\\CIMV2"), // Object path of WMI namespace
			NULL,                    // User name. NULL = current user
			NULL,                    // User password. NULL = current
			0,                       // Locale. NULL indicates current
			NULL,                    // Security flags.
			0,                       // Authority (for example, Kerberos)
			0,                       // Context object 
			&pSvc                    // pointer to IWbemServices proxy
		);
		if (FAILED(hr))
		{
			pLoc->Release();
			CoUninitialize();
			throw "Could not connect to ROOT\\CIMv2 WMI namespace.";
		}

		// Step 5: --------------------------------------------------
		// Set security levels on the proxy -------------------------

		hr = CoSetProxyBlanket(
			pSvc,                        // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
			NULL,                        // Server principal name 
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities 
		);
		if (FAILED(hr))
		{
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			throw "Could not set proxy blanket.";
		}
		return 0;
	}
	catch (const char *msg)
	{
		std::cerr << "ERROR: " << msg << std::endl;
		return EXIT_FAILURE;
	}
}


void cleanWmiConnection()
{
	pLoc->Release();
	pSvc->Release();
	CoUninitialize();
}


int getApp(const int pid, string &appname)
{
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx
	// http://www.cplusplus.com/forum/windows/45564/
	//! @warning  we can't reliably get the command line information (see http://stackoverflow.com/a/6522047)
#if 0
	//! @note It is the same thing with OpenProcess, you can't open a process which is a service or a process opened by SYSTEM or LOCAL SERVICE or NETWORK SERVICE, if you are running your program by a user (even administrator).
	//!    If your program is a service, it is probably already running by local system account, so no problem.But if not, a solution is to launch it with psexec :
	//! (see http://stackoverflow.com/a/42341811)

	HANDLE pHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (pHandle == 0)
	{
		log(LogLevel::ERR, "Can't open process with pid: ", pid);
		return -1;
	}
	HINSTANCE hinstLib = nullptr;
	
	try
	{
		MYPROC ProcAddr = nullptr;
		
		// Get a handle to the DLL module.
		hinstLib = LoadLibrary(TEXT("Ntdll.dll"));

		// If the handle is valid, try to get the function address.
		if (hinstLib == nullptr)
			throw "Can't get handle to Ntdll.dll module.";

		ProcAddr = (MYPROC)GetProcAddress(hinstLib, "NtQueryInformationProcess");
		// If the function address is valid, call the function.
		if (nullptr == ProcAddr)
			throw "Can't get NtQueryInformationProcess address from dll module.";
		
		ULONG processInfoSize = 0;
		(ProcAddr)(pHandle, ProcessBasicInformation, nullptr, 0, &processInfoSize);
		PROCESS_BASIC_INFORMATION *pebStruct = (PROCESS_BASIC_INFORMATION*) new char[processInfoSize];
		if ((ProcAddr)(pHandle, ProcessBasicInformation, pebStruct, processInfoSize, &processInfoSize))
		{
			delete pebStruct;
			throw "Can't get process information.";
		}

		UNICODE_STRING determinedAppname = pebStruct->PebBaseAddress->ProcessParameters->CommandLine;
		int size_needed = WideCharToMultiByte(CP_UTF8, 0, determinedAppname.Buffer, determinedAppname.Length, NULL, 0, NULL, NULL);
		std::string strTo(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, determinedAppname.Buffer, determinedAppname.Length, &strTo[0], size_needed, NULL, NULL);
		appname = strTo;

		delete pebStruct;
		// Free the DLL module.
		FreeLibrary(hinstLib);
		CloseHandle(pHandle);
		return 0;
	}
	catch (const char *msg)
	{
		std::cerr << "ERROR: " << msg << std::endl;
		if (pHandle)
			CloseHandle(pHandle);
		if (hinstLib)
			FreeLibrary(hinstLib);
		return EXIT_FAILURE;
	}
#else
	//! @todo WMI implement
	//https://stackoverflow.com/questions/9589431/getting-the-command-line-arguments-of-another-process-in-windows
	//https://stackoverflow.com/questions/1999765/how-can-i-execute-this-wmi-query-in-vc
	//https://msdn.microsoft.com/en-us/library/aa389762(v=vs.85).aspx
	//https://msdn.microsoft.com/en-us/library/aa390423(v=vs.85).aspx
	//https://msdn.microsoft.com/en-us/library/aa394558(v=vs.85).aspx
	//https://msdn.microsoft.com/en-us/library/aa394372%28v=VS.85%29.aspx
	//! @warning ...just "preinitialized variable", a process could in principle 
	//! (and many do in practice, although usually inadvertently) write to the memory 
	//! that holds the command line
	//https://blogs.msdn.microsoft.com/oldnewthing/20091125-00/?p=15923/

	HRESULT hr;
	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	IEnumWbemClassObject *pEnumerator = NULL;
	bstr_t query(string("SELECT CommandLine FROM Win32_Process WHERE ProcessId = '" + std::to_string(pid) + "'").c_str());
	hr = pSvc->ExecQuery(L"WQL", query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hr))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		std::cerr << "ExecQuery failed." << std::endl;
		return EXIT_FAILURE;
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj = nullptr;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn || FAILED(hr))
			break;

		VARIANT vtProp;

		hr = pclsObj->Get(L"CommandLine", 0, &vtProp, 0, 0);// String
		if (!FAILED(hr))
		{
			if ((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY))
				log(LogLevel::ERR, "Application not found for pid <", pid, ">");//std::cout << "CommandLine : " << ((vtProp.vt == VT_NULL) ? "NULL" : "EMPTY") << std::endl;
			else
			{
				if ((vtProp.vt & VT_ARRAY))
					log(LogLevel::ERR, "Array types are not supported (yet)");
				else
					appname = ConvertBSTRToMBS(vtProp.bstrVal);
			}
		}
		VariantClear(&vtProp);

		pclsObj->Release();
		pclsObj = NULL;
	}

	// Cleanup
	pEnumerator->Release();
	if (pclsObj != NULL)
		pclsObj->Release();
	return 0;
#endif
}


}	// namespace TOOL
