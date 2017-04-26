/** 
 *  @file       cache.cpp
 *  @brief      Cache implementation sources
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 26.02.2017 23:52
 *   - Edited:  25.04.2017 16:36
 */

#include <iostream>             //  cout, endl;
#include <atomic>               //  atomic
#include <map>                  //  map

#if defined(__linux__)
#include <cstring>              //  memcmp(), memcpy()

#elif defined(_WIN32)
//#include <Winsock2.h>			//	in_addr, AF_INET
#endif

#include "tcpip_headers.hpp"	//	ip4_addr, ip6_addr, 
#include "netflow.hpp"          //  Netflow
#include "debug.hpp"            //  log()
#include "cache.hpp"            //  Cache
#include "utils.hpp"			//  inet_ntop()


using namespace std;


extern map<string, vector<TOOL::Netflow *>> g_finalResults;
extern const atomic<int> shouldStop;




namespace TOOL
{


const int VALID_TIME = 10;      //!< Time of validity of TEntry record in cache in seconds



/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
 *                                                                            *
 *                           class TEntryOrTree                               *
 *                                                                            *
 *++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/



/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
 *                                                                            *
 *                                 class TEntry                               *
 *                                                                            *
 *++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
bool TEntry::levelCompare(Netflow *n1)
{
    switch(level)
    {
        case TreeLevel::LOCAL_PORT:
        {
            return n->getLocalPort() == n1->getLocalPort();
        }
        case TreeLevel::PROTO:
        {
            return n->getProto() == n1->getProto();
        }
        case TreeLevel::LOCAL_IP:
        {
            if (n->getIpVersion() == 4)
                return static_cast<ip4_addr*>(n->getLocalIp())->addr == static_cast<ip4_addr*>(n1->getLocalIp())->addr;
            else if (n->getIpVersion() == 6)
                return !memcmp(n->getLocalIp(), n1->getLocalIp(), IPv6_ADDRLEN);
            else
                throw "Should not came in here"; //! @todo catch
        }
        default:
            throw "Should not came in here"; //! @todo catch
    }
}



void TEntry::print()
{

    cout << string((int)level, '-') << ">[" << (int)level << "] \"" << appName << "\" (inode/PID:" << inodeOrPid << ")\t"/* << (valid() ? "(valid)" : "(expired)") << "\t"*/;
    n->print();
}



/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
 *                                                                            *
 *                                  class TTree                               *
 *                                                                            *
 *++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
TTree::~TTree() 
{ 
    for (auto ptr : v)
        delete ptr; 
    v.clear(); 
    if (level == TreeLevel::LOCAL_IP)
    {
        if (ipVersion == 4)
            delete static_cast<ip4_addr*>(cv.ip);
        else if (ipVersion == 6)
            delete static_cast<ip6_addr*>(cv.ip);
        else
            throw "Should not came in here";  //! @todo catch
    }
}


TEntryOrTTree * TTree::find(Netflow &n)
{
    for (auto ptr : v)
    {
        if (ptr->levelCompare(&n))
        {
            if (ptr->isEntry())
            {
                if (*static_cast<TEntry*>(ptr)->getNetflowPtr() == n)
                    return ptr;
                else
                    return this;
            }
            return static_cast<TTree*>(ptr)->find(n);
        }
    }
    return this;
}


void TTree::insert(TEntry *newEntry)
{
    for (vector<TEntryOrTTree*>::size_type i=0; i < v.size(); i++)
    {
        if (v[i]->levelCompare(newEntry->getNetflowPtr()))
        {
            if (v[i]->isEntry())
            {
                TEntry *oldEntry = static_cast<TEntry*>(v[i]);
                if (*oldEntry->getNetflowPtr() == *newEntry->getNetflowPtr())
                {
                    log(LogLevel::ERR, "TTree::insert called two times with the same Netflow.");//! @todo what to do?
                    return;
                }
                // Create a new tree
                v[i] = new TTree(oldEntry->getLevel());
                // Set common value at that level
                static_cast<TTree*>(v[i])->setCommonValue(oldEntry->getNetflowPtr());
                // Insert an old entry with the new one
                static_cast<TTree*>(v[i])->insert(oldEntry);
                static_cast<TTree*>(v[i])->insert(newEntry);
                return;
            }
            else
            {
                static_cast<TTree*>(v[i])->insert(newEntry);
                return;
            }
        }
    }
    // If there is no element with the same value on its level then add a new one
    newEntry->setLevel(level+1);
    v.push_back(newEntry);
}


void TTree::setCommonValue(Netflow *n)
{
    switch(level)
    {
        case TreeLevel::LOCAL_PORT:
        {
            setPort(n->getLocalPort());
            break;
        }
        case TreeLevel::PROTO:
        {
            setProto(n->getProto());
            break;
        }
        case TreeLevel::LOCAL_IP:
        {   // WARNING:    If it is called two times on the same level, it will cause a memory leak
            unsigned char ipVersion = n->getIpVersion();
            if (ipVersion == 4)
            {
                ip4_addr *tmpIpPtr = new ip4_addr;
                tmpIpPtr->addr = static_cast<ip4_addr*>(n->getLocalIp())->addr;
                setIp(tmpIpPtr, ipVersion);
            }
            else if (ipVersion == 6)
            {
                ip6_addr *tmpIpPtr = new ip6_addr;
                memcpy(tmpIpPtr, n->getLocalIp(), IPv6_ADDRLEN);
                setIp(tmpIpPtr, ipVersion);
            }
            else
                throw "Should not came in here"; //! @todo catch
            break;
        }
        default:
            throw "Should not came in here"; //! @todo catch
    }
}


bool TTree::levelCompare(Netflow *n)
{
    switch(level)
    {
        case TreeLevel::LOCAL_PORT:
        {
            return cv.port == n->getLocalPort();
        }
        case TreeLevel::PROTO:
        {
            return cv.proto == n->getProto();
        }
        case TreeLevel::LOCAL_IP:
        {
            if (n->getIpVersion() != ipVersion)
                return false;
            if (ipVersion == 4)
                return static_cast<ip4_addr*>(cv.ip)->addr == static_cast<ip4_addr*>(n->getLocalIp())->addr;
            else if (ipVersion == 6)
                return !memcmp(cv.ip, n->getLocalIp(), IPv6_ADDRLEN);
            else
                throw "Should not come in here"; //! @todo catch
        }
        default:
            throw "Should not come in here"; //! @todo catch
    }
}


void TTree::saveResults()
{
    for (auto record : v)
    {
        if (record->isEntry())
        {
            TEntry *entryPtr = static_cast<TEntry *>(record);
            if (entryPtr->getAppName() != "")
            {
                Netflow *res = new Netflow;
                *res = *entryPtr->getNetflowPtr();
                g_finalResults[entryPtr->getAppName()].push_back(res);
            }
        }
        else
            static_cast<TTree *>(record)->saveResults();
    }
}


void TTree::print()
{
    cout << string((int)level, '-') << ">{" << (int)level << "} ";
    switch(level)
    {
        case TreeLevel::LOCAL_PORT:
            cout << "Port: <" << cv.port;
            break;
        case TreeLevel::PROTO:
            cout << "Protocol: <" << (int)cv.proto;
            break;
        case TreeLevel::LOCAL_IP:
        {
            if (ipVersion == 4)
            {
                char str[IPv4_ADDRSTRLEN];
				inet_ntop(AF_INET, cv.ip, str, IPv4_ADDRSTRLEN);
                cout << "IPv4: <" << str;
            }
            else if (ipVersion == 6)
            {
                char str[IPv6_ADDRSTRLEN];
                inet_ntop(AF_INET6, cv.ip, str, IPv6_ADDRSTRLEN);
                cout << "IPv6: <" <<str;
            }
            else
                throw "Should not came in here";
            break;
        }
    }
    cout << ">" << endl;
    
    for (auto ptr : v)
        ptr->print();
}



/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
 *                                                                            *
 *                                  class Cache                               *
 *                                                                            *
 *++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
Cache::~Cache()                        
{ 
    for (auto ptr : *map)
        delete ptr.second;
    delete map; 
}


TEntryOrTTree *Cache::find(Netflow &n)
{
    auto iter = map->find(n.getLocalPort());
    // if the netflow record either exists in the cache or there is a netflow with the same local port
    if (iter != (*map).end())
    {
        if (iter->second->isTree())
            return static_cast<TTree*>(iter->second)->find(n);
        else    // isEntry -> record exists
        {
            TEntry *entry = static_cast<TEntry*>(iter->second);
            // If exactly the same netflow record already exists
            if (*(entry->getNetflowPtr()) == n)
                return entry;
            else
                return nullptr;
        }
    }
    else
        return nullptr;
}


void Cache::insert(TEntry *newEntry)
{
    Netflow &newNetflow = *newEntry->getNetflowPtr();
    auto iter = map->find(newNetflow.getLocalPort());
    if (iter != (*map).end())
    { // Netflow record either exists in the cache (at least with the same local port)
        if (iter->second->isTree())
        { // insert it into a subtree
            static_cast<TTree*>(iter->second)->insert(newEntry);
        }
        else    
        { // isEntry -> record with the same local port
            TEntry *oldEntry = static_cast<TEntry*>(iter->second);
            // If the same netflow record already exists
            if (*oldEntry->getNetflowPtr() == newNetflow)
                log(LogLevel::ERR, "Cache::insert called two times with the same Netflow.");//! @todo what to do?
            else
            {
                // Create a new tree
                TTree *newTree = new TTree(oldEntry->getLevel());
                newTree->setCommonValue(oldEntry->getNetflowPtr());
                // Insert an old entry with the new one
                newTree->insert(oldEntry);
                newTree->insert(newEntry);
                iter->second = newTree;
            }
        }
    }
    else
    { // there isn't record with the same local port in the map
        newEntry->setLevel(TreeLevel::LOCAL_PORT);
        (*map)[newNetflow.getLocalPort()] = newEntry;
    }
}


void Cache::saveResults()
{
    for (auto record : *map)
    {
        if (record.second->isEntry())
        {
            TEntry *entryPtr = static_cast<TEntry *>(record.second);
            if (/*!entryPtr->valid() && */entryPtr->getAppName() != "")
            {
                Netflow *res = new Netflow;
                *res = *entryPtr->getNetflowPtr();
                g_finalResults[entryPtr->getAppName()].push_back(res);
            }
        }
        else
            static_cast<TTree *>(record.second)->saveResults();
    }
}


void Cache::print()
{
    for (auto m : *map)
        m.second->print();
}


}	// namespace TOOL
