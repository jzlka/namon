/** 
 *  @file       tool_win.tpp
 *  @brief      Windows related template functions
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 19.04.2017 17:38
 *   - Edited:  20.04.2017 08:34
 */


template<typename TABLE, typename ROW>
int getTcpConnectionOwner(Netflow *n, int family)
{
	DWORD tableSize = 0;
	
	GetExtendedTcpTable(nullptr, &tableSize, FALSE, family, TCP_TABLE_CLASS, 0);
	TABLE table = (TABLE) new char[tableSize];
	if (GetExtendedTcpTable(table, &tableSize, FALSE, family, TCP_TABLE_CLASS, 0) != NO_ERROR)
	{
		log(LogLevel::ERR, "Unable to get connections table");
		delete table;
		return -1;
	}
	for (int i = 0; i < table->dwNumEntries; i++)
	{
		const ROW &row = table->table[i];
		if (row.dwLocalPort == n->getLocalPort())
		{
			if (row.dwLocalAddr == (*(in_addr*)n->getLocalIp()).S_un.S_addr)
			{
				!memcmp(row.ucLocalAddr, n->getLocalIp(), IPv6_ADDRLEN);
				delete table;
				return row.dwOwningPid;
			}
		}
	}
	delete table;
	return 0;		
}

template<typename TABLE, typename ROW>
int getUdpConnectionOwner(Netflow *n, int family)
{
	DWORD tableSize = 0;
	
	GetExtendedUdpTable(nullptr, &tableSize, FALSE, family, UDP_TABLE_CLASS, 0);
	TABLE table = (TABLE) new char[tableSize];
	if (GetExtendedUdpTable(table, &tableSize, FALSE, family, UDP_TABLE_CLASS, 0) != NO_ERROR)
	{
		log(LogLevel::ERR, "Unable to get connections table");
		delete table;
		return -1;
	}
	for (int i = 0; i < table->dwNumEntries; i++)
	{
		const ROW &row = table->table[i];
		if (row.dwLocalPort == n->getLocalPort())
		{
			if (row.dwLocalAddr == (*(in_addr*)n->getLocalIp()).S_un.S_addr)
			{
				!memcmp(row.ucLocalAddr, n->getLocalIp(), IPv6_ADDRLEN);
				delete table;
				return row.dwOwningPid;
			}
		}
	}
	delete table;
	return 0;		
}
