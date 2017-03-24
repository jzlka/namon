/** 
 *  @file       cache.cpp
 *  @brief      Cache implementation sources
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:52
 *  Edited:     23.03.2017 19:06
 *  Version:    1.0.0
 */

#include <iostream>             //  cout, endl;
#include <fstream>              //  ostream
#include <thread>               //  sleep_for
#include "netflow.hpp"          //  Netflow
#include "debug.hpp"            //  log()
#include "cache.hpp"            //  Cache

#if defined(__linux__)
#include <cstring>              //  memcmp(), memcpy()
#endif

using namespace std;
using std::chrono::seconds;
using std::chrono::duration_cast;


extern const int shouldStop;
const int UPDATE_INTERVAL = 5;      //!< Cache will be updated every >#UPDATE_INTERVAL< seconds



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
                return !memcmp(n->getLocalIp(), n1->getLocalIp(), sizeof(struct in_addr));
            else if (n->getIpVersion() == 6)
                return !memcmp(n->getLocalIp(), n1->getLocalIp(), sizeof(struct in6_addr));
            else
                throw "Should not came in here";
        }
        default:
            throw "Should not came in here";
    }
}
unsigned int TEntry::write(std::ofstream & file)
{
    unsigned int writtenBytes = 0;
    size_t size = appName.size();
    file.write(reinterpret_cast<char*>(&size), sizeof(size));
    writtenBytes += sizeof(size);
    file.write(appName.c_str(), size);
    writtenBytes += size;

    size = sizeof(inode);
    file.write(reinterpret_cast<char*>(&inode), size);
    writtenBytes += size;

#if 0
    writtenBytes += n->write(file);
#else
    size = sizeof(n->ipVersion);
    file.write(reinterpret_cast<char*>(&n->ipVersion), size);
    writtenBytes += size;

    //! @todo Can ipVersion contain other number?
    size = (n->ipVersion == 4) ? sizeof(in_addr) : sizeof(in6_addr);
    file.write(reinterpret_cast<char*>(n->localIp), size);
    writtenBytes += size;

    size = sizeof(n->localPort);
    file.write(reinterpret_cast<char*>(&n->localPort), size);
    writtenBytes += size;

    size = sizeof(n->proto);
    file.write(reinterpret_cast<char*>(&n->proto), size);
    writtenBytes += size;

    size = sizeof(n->startTime);
    file.write(reinterpret_cast<char*>(&n->startTime), size);
    file.write(reinterpret_cast<char*>(&n->endTime), size);
    writtenBytes += size + size;
#endif

    return writtenBytes;
}

void TEntry::print()
{
    cout << string((int)level, '-') << ">[" << (int)level << "] \"" << appName << "\" (inode:" << inode << ")\t";
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
            delete static_cast<in_addr*>(cv.ip);
        else if (ipVersion == 6)
            delete static_cast<in6_addr*>(cv.ip);
        else
            throw "Should not came in here";
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

void TTree::insert(TEntry *entry)
{
    for (vector<TEntryOrTTree*>::size_type i=0; i < v.size(); i++)
    {
        if (v[i]->isEntry() && v[i]->levelCompare(entry->getNetflowPtr()))
        {
            TEntry *oldEntry = static_cast<TEntry*>(v[i]);
            // Create a new tree
            v[i] = new TTree(oldEntry->getLevel());
            // Set common value at that level
            static_cast<TTree*>(v[i])->setCommonValue(oldEntry->getNetflowPtr());
            // Insert an old entry with the new one
            static_cast<TTree*>(v[i])->insert(oldEntry);
            static_cast<TTree*>(v[i])->insert(entry);
            return;
        }
        // else if isTree() or it doesn't have same lvl value just ignore it
        // We ignore TTree because find returns TTree with the closest match
        // so we don't have to go deeplier in the tree (Node we are interested
        // in is a TEntry). 
        // We also ignore it if it is at the LOCAL_IP level, because we don't care
        // about remote site of the connection
    }
    // If there is no element with the same value on its level then add a new one
    entry->setLevel(level+1);
    v.push_back(entry);
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
        {   //! @warning    If it is called two times on the same level, it will cause a memory leak
            unsigned char ipVersion = n->getIpVersion();
            if (ipVersion == 4)
            {
                in_addr *tmpIpPtr = new in_addr;
                memcpy(tmpIpPtr, n->getLocalIp(), sizeof(in_addr));
                setIp(tmpIpPtr, ipVersion);
            }
            else if (ipVersion == 6)
            {
                in6_addr *tmpIpPtr = new in6_addr;
                memcpy(tmpIpPtr, n->getLocalIp(), sizeof(in6_addr));
                setIp(tmpIpPtr, ipVersion);
            }
            else
                throw "Should not came in here";
            break;
        }
        default:
            throw "Should not came in here";
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
                return !memcmp(cv.ip, n->getLocalIp(), sizeof(struct in_addr));
            else if (ipVersion == 6)
                return !memcmp(cv.ip, n->getLocalIp(), sizeof(struct in6_addr));
            else
                throw "Should not come in here";
        }
        default:
            throw "Should not come in here";
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
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, cv.ip, str, INET_ADDRSTRLEN);
                cout << "IPv4: <" << str;
            }
            else if (ipVersion == 6)
            {
                char str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, cv.ip, str, INET6_ADDRSTRLEN);
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
    for (auto ptr : *cache)
        delete ptr.second;
    delete cache; 
}

TEntryOrTTree *Cache::find(Netflow &n)
{
    auto iter = cache->find(n.getLocalPort());
    // if the netflow record either exists in the cache or there is a netflow with the same local port
    if (iter != (*cache).end())
    {
        if (iter->second->isTree())
            return static_cast<TTree*>(iter->second)->find(n);
        else    // isEntry -> record exists
        {
            TEntry *entry = static_cast<TEntry*>(iter->second);
            // If the same netflow record already exists, update endTime
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
    Netflow *newNetflow = newEntry->getNetflowPtr();
    auto iter = (*cache).find(newNetflow->getLocalPort());
    if (iter != (*cache).end())
    {   // the netflow record either exists in the cache or there is a netflow with the same local port
        if (iter->second->isTree())
        {
            TEntryOrTTree *found = static_cast<TTree*>(iter->second)->find(*newNetflow);
            // If the same entry already exists
            if (found->isEntry()) 
                log(LogLevel::ERROR, "TTree::insert called two times with the same Netflow.");//! @todo what to do?
            // ^^^ in this case we do not update endTime because insert() is used while creating a new tree 
            // and in this case there mustn't be two same Netflow structures (that would mean two same sockets)
            else
                static_cast<TTree*>(found)->insert(newEntry);
        }
        else    // isEntry -> record already exists
        {
            TEntry *oldEntry = static_cast<TEntry*>(iter->second);
            // If the same netflow record already exists (compares just relevant variables)
            if (*(oldEntry->getNetflowPtr()) == *newNetflow)
                log(LogLevel::ERROR, "Cache::insert called two times with the same Netflow.");//! @todo what to do?
            // ^^^ in this case we do not update endTime because insert() is used while creating a new tree 
            // and in this case there mustn't be two same Netflow structures (that would mean two same sockets)
            else
            {
                // Create a new tree
                iter->second = new TTree(oldEntry->getLevel());
                static_cast<TTree*>(iter->second)->setCommonValue(oldEntry->getNetflowPtr());
                // Insert an old entry with the new one
                static_cast<TTree*>(iter->second)->insert(oldEntry);
                static_cast<TTree*>(iter->second)->insert(newEntry);
            }
        }
    }
    else
    {
        newEntry->setLevel(TreeLevel::LOCAL_PORT);
        (*cache)[newNetflow->getLocalPort()] = newEntry;
    }
}

void Cache::periodicUpdate()
{
    while(!shouldStop)
    {
        // If it has been already updated (e.g. because of cache miss) don't update it
        if(duration_cast<seconds>(clock_type::now()-lastUpdate) >= seconds(UPDATE_INTERVAL))  
            this_thread::sleep_for(seconds(UPDATE_INTERVAL));
        // If shoudStop was set during sleep
        if(!shouldStop)
            break;

        //map<unsigned short, TEntryOrTTree*> *newCache = new map<unsigned short, TEntryOrTTree*>;
        //::initCache(this);
        //diff();
        //! @todo   Implement cache.diff and periodicUpdate
    }
}

void Cache::print()
{
    cout << lastUpdate.time_since_epoch().count() << endl;

    for (auto m : *cache)
        m.second->print();
}
