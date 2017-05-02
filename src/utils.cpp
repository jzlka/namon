/**
 *  @file       utils.cpp
 *  @brief      Small useful functions
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 28.03.2017 14:14
 *   - Edited:  20.04.2017 08:23
 */

#include <cctype>				//  isdigit()

#if defined(__APPLE__) || defined(__linux__)
#include <cstring>		// memset(), strlen() #linux

#elif defined(_WIN32)
//#include <WinSock2.h>			//	
#endif

#include "tcpip_headers.hpp"	//	IPv4_ADDRSTRLEN
#include "debug.hpp"			//	log()




namespace TOOL
{


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



int inet_ntop4(const void *src, char *dst, size_t size)
{
	const unsigned char *srcaddr = (const unsigned char *)src;
	const char digits[] = "0123456789";

	if (size < IPv4_ADDRSTRLEN)
		return -1;
	
	for (int i = 0; i < IPv4_ADDRLEN; ++i) 
	{
		int n = *srcaddr++;
		int non_zerop = 0;

		if (non_zerop || n / 100 > 0) 
		{
			*dst++ = digits[n / 100];
			n %= 100;
			non_zerop = 1;
		}
		if (non_zerop || n / 10 > 0) 
		{
			*dst++ = digits[n / 10];
			n %= 10;
			non_zerop = 1;
		}
		*dst++ = digits[n]; //! @todo n+'0'
		if (i != 3)
			*dst++ = '.';
	}
	*dst++ = '\0';
	return 0;
}


int inet_ntop6(const void *src, char *dst, size_t size)
{
	const unsigned char *srcaddr = (const unsigned char *)src;
	char *dp;
	size_t space_left, added_space;
	int snprintfed;
	const int int16sz = sizeof(int16_t);
	struct {
		long base;
		long len;
	} best, cur;
	unsigned long words[IPv6_ADDRLEN / int16sz];
	unsigned int  i;

	/* Preprocess:
	*  Copy the input (bytewise) array into a wordwise array.
	*  Find the longest run of 0x00's in src[] for :: shorthanding.
	*/
	memset(words, 0, sizeof(words));
	for (i = 0; i < IPv6_ADDRLEN; i++)
		words[i / 2] |= (srcaddr[i] << ((1 - (i % 2)) << 3));

	best.len = 0;
	best.base = -1;
	cur.len = 0;
	cur.base = -1;
	for (i = 0; i < (IPv6_ADDRLEN / int16sz); i++)
	{
		if (words[i] == 0)
		{
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else cur.len++;
		}
		else if (cur.base != -1)
		{
			if (best.base == -1 || cur.len > best.len)
				best = cur;
			cur.base = -1;
		}
	}
	if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
		best = cur;
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/* Format the result.
	*/
	dp = dst;
	space_left = size;
#define APPEND_CHAR(c) \
    { \
        if (space_left == 0) { \
            errno = ENOSPC; \
            return (0); \
        } \
        *dp++ = c; \
        space_left--; \
    }
	for (i = 0; i < (IPv6_ADDRLEN / int16sz); i++)
	{
		/* Are we inside the best run of 0x00's?
		*/
		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
				APPEND_CHAR(':');
			continue;
		}

		/* Are we following an initial run of 0x00s or any real hex?
		*/
		if (i != 0)
			APPEND_CHAR(':');

		/* Is this address an encapsulated IPv4?
		*/
		if (i == 6 && best.base == 0 &&
			(best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
		{
			if (!inet_ntop4(srcaddr + 12, dp, space_left))
			{
				return -1;
			}
			added_space = strlen(dp);
			dp += added_space;
			space_left -= added_space;
			break;
		}
		snprintfed = snprintf(dp, space_left, "%lx", words[i]);
		if (snprintfed < 0)
			return -1;
		if ((size_t)snprintfed >= space_left)
		{
			return -1;
		}
		dp += snprintfed;
		space_left -= snprintfed;
	}

	/* Was it a trailing run of 0x00's?
	*/
	if (best.base != -1 && (best.base + best.len) == (IPv6_ADDRLEN / int16sz))
		APPEND_CHAR(':');
	APPEND_CHAR('\0');

	return 0;
}


int inet_ntop(const int af, const void *src, char *dst, size_t size)
{
	if (af == AF_INET)
		return inet_ntop4(src, dst, size);
	else if (af == AF_INET6)
		return inet_ntop6(src, dst, size);

	log(LogLevel::ERR, "inet_ntop: Unexpected address family");
	return -1;
}


}	// namespace TOOL
