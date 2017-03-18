/** 
 *  @file       cache.cpp
 *  @brief      Cache implementation sources
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:52
 *  Edited:     18.03.2017 10:48
 *  Version:    1.0.0
 */

#include <iostream>             //  cout, endl;
#include <thread>               //  sleep_for
#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache
#include "debug.hpp"            //  log()

#if defined(__linux__)
#include "tool_linux.hpp"       //  initCache()
#endif
#if defined(__FreeBSD__)
#include "tool_bsd.hpp"
#endif
#if defined(__APPLE__)
#include "tool_apple.hpp"
#endif
#if defined(WIN32) || defined(WINx64) || (defined(__MSDOS__) || defined(__WIN32__))
#include "tool_win.hpp"
#endif


using namespace std;
using std::chrono::seconds;
using std::chrono::duration_cast;

extern const int shouldStop;
const int UPDATE_INTERVAL = 5;



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
            if (n->getDir() == Directions::INBOUND)
                return n->getDstPort() == n1->getDstPort();
            else
                return n->getSrcPort() == n1->getSrcPort();
        }
        case TreeLevel::PROTO:
        {
            return n->getProto() == n1->getProto();
        }
        case TreeLevel::LOCAL_IP:
        {
            if (n->getIpVersion() == 4)
            {
                in_addr *tmpPtr, *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                {
                    tmpPtr = static_cast<in_addr*>(n->getDstIp());
                    tmpPtr2 = static_cast<in_addr*>(n1->getDstIp());
                }
                else
                {
                    tmpPtr = static_cast<in_addr*>(n->getSrcIp());
                    tmpPtr2 = static_cast<in_addr*>(n1->getSrcIp());
                }
                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else if (n->getIpVersion() == 6)
            {
                in6_addr *tmpPtr, *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                {
                    tmpPtr = static_cast<in6_addr*>(n->getDstIp());
                    tmpPtr2 = static_cast<in6_addr*>(n1->getDstIp());

                }
                else
                {
                    tmpPtr = static_cast<in6_addr*>(n->getSrcIp());
                    tmpPtr2 = static_cast<in6_addr*>(n1->getSrcIp());
                }
                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
            else
                throw "Should not came in here";
        }
        case TreeLevel::REMOTE_IP:
        {
            if (n->getIpVersion() == 4)
            {
                in_addr *tmpPtr, *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                {
                    tmpPtr = static_cast<in_addr*>(n->getSrcIp());
                    tmpPtr2 = static_cast<in_addr*>(n1->getSrcIp());
                }
                else
                {
                    tmpPtr = static_cast<in_addr*>(n->getDstIp());
                    tmpPtr2 = static_cast<in_addr*>(n1->getDstIp());
                }
                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else if (n->getIpVersion() == 6)
            {
                in6_addr *tmpPtr, *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                {
                    tmpPtr = static_cast<in6_addr*>(n->getSrcIp());
                    tmpPtr2 = static_cast<in6_addr*>(n1->getSrcIp());
                }
                else
                {
                    tmpPtr = static_cast<in6_addr*>(n->getDstIp());
                    tmpPtr2 = static_cast<in6_addr*>(n1->getDstIp());
                }
                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
            else
                throw "Should not came in here";
        }
        case TreeLevel::REMOTE_PORT:
        {
            if (n->getDir() == Directions::INBOUND)
                return n->getSrcPort() == n1->getSrcPort();
            else
                return n->getDstPort() == n1->getDstPort();
        }
    }
}

void TEntry::print()
{
    cout << string((int)level, '-') << ">[" << (int)level << "] \"" << appName << "\" (inode:" << inode << ")\t";
    if (n != nullptr)
        n->print();
    else
        cout << endl;
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
    if (level == TreeLevel::LOCAL_IP || level == TreeLevel::REMOTE_IP)
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
            if (n->getDir() == Directions::INBOUND)
                setPort(n->getDstPort());
            else
                setPort(n->getSrcPort());
            break;
        }
        case TreeLevel::PROTO:
        {
            setProto(n->getProto());
            break;
        }
        case TreeLevel::LOCAL_IP:
        {   // FIXME if it is called two times on the same level there will be a memory leak
            unsigned char ipVersion = n->getIpVersion();
            if (ipVersion == 4)
            {
                in_addr *tmpIpPtr = new in_addr;
                if (n->getDir() == Directions::INBOUND)
                    memcpy(tmpIpPtr, n->getDstIp(), sizeof(in_addr));
                else
                    memcpy(tmpIpPtr, n->getSrcIp(), sizeof(in_addr));
                setIp(tmpIpPtr, ipVersion);
            }
            else if (ipVersion == 6)
            {
                in6_addr *tmpIpPtr = new in6_addr;
                if (n->getDir() == Directions::INBOUND)
                    memcpy(tmpIpPtr, n->getDstIp(), sizeof(in6_addr));
                else
                    memcpy(tmpIpPtr, n->getSrcIp(), sizeof(in6_addr));
                setIp(tmpIpPtr, ipVersion);
            }
            else
                throw "Should not came in here";
            break;
        }
        case TreeLevel::REMOTE_IP:
        {   // FIXME if it is called two times on the same level there will be a memory leak
            unsigned char ipVersion = n->getIpVersion();
            if (ipVersion == 4)
            {
                in_addr *tmpIpPtr = new in_addr;
                if (n->getDir() == Directions::INBOUND)
                    memcpy(tmpIpPtr, n->getSrcIp(), sizeof(in_addr));
                else
                    memcpy(tmpIpPtr, n->getDstIp(), sizeof(in_addr));
                setIp(tmpIpPtr, ipVersion);
            }
            else if (ipVersion == 6)
            {
                in6_addr *tmpIpPtr = new in6_addr;
                if (n->getDir() == Directions::INBOUND)
                    memcpy(tmpIpPtr, n->getSrcIp(), sizeof(in6_addr));
                else
                    memcpy(tmpIpPtr, n->getDstIp(), sizeof(in6_addr));
                setIp(tmpIpPtr, ipVersion);
            }
            else
                throw "Should not came in here";
            break;
        }
        case TreeLevel::REMOTE_PORT:
        {
            if (n->getDir() == Directions::INBOUND)
                setPort(n->getSrcPort());
            else
                setPort(n->getDstPort());
            break;
        }
    }
}

bool TTree::levelCompare(Netflow *n)
{
    switch(level)
    {
        case TreeLevel::LOCAL_PORT:
        {
            if (n->getDir() == Directions::INBOUND)
                return cv.port == n->getDstPort();
            else
                return cv.port == n->getSrcPort();
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
            {
                in_addr *tmpPtr, *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                {
                    tmpPtr = static_cast<in_addr*>(cv.ip);
                    tmpPtr2 = static_cast<in_addr*>(n->getDstIp());
                }
                else
                {
                    tmpPtr = static_cast<in_addr*>(cv.ip);
                    tmpPtr2 = static_cast<in_addr*>(n->getSrcIp());
                }
                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else if (ipVersion == 6)
            {
                in6_addr *tmpPtr, *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                {
                    tmpPtr = static_cast<in6_addr*>(cv.ip);
                    tmpPtr2 = static_cast<in6_addr*>(n->getDstIp());
                }
                else
                {
                    tmpPtr = static_cast<in6_addr*>(cv.ip);
                    tmpPtr2 = static_cast<in6_addr*>(n->getSrcIp());
                }
                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
            else
                throw "Should not come in here";
        }
        case TreeLevel::REMOTE_IP:
        {
            if (n->getIpVersion() != ipVersion)
                return false;
            if (ipVersion == 4)
            {
                in_addr *tmpPtr = static_cast<in_addr*>(cv.ip);
                in_addr *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                    tmpPtr2 = static_cast<in_addr*>(n->getSrcIp());
                else
                    tmpPtr2 = static_cast<in_addr*>(n->getDstIp());

                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else if (ipVersion == 6)
            {
                in6_addr *tmpPtr = static_cast<in6_addr*>(cv.ip);
                in6_addr *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                    tmpPtr2 = static_cast<in6_addr*>(n->getSrcIp());
                else
                    tmpPtr2 = static_cast<in6_addr*>(n->getDstIp());

                return !memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
            else
                throw "Should not came in here";
        }
        case TreeLevel::REMOTE_PORT:
        {
            if (n->getDir() == Directions::INBOUND)
                return cv.port == n->getSrcPort();
            else
                return cv.port == n->getDstPort();
        }
    }
}

void TTree::print()
{
    cout << string((int)level, '-') << ">{" << (int)level << "} ";
    switch(level)
    {
        case TreeLevel::LOCAL_PORT:
        case TreeLevel::REMOTE_PORT:
            cout << "Port: <" << cv.port;
            break;
        case TreeLevel::PROTO:
            cout << "Protocol: <" << (int)cv.proto;
            break;
        case TreeLevel::LOCAL_IP:
        case TreeLevel::REMOTE_IP:
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
Cache::Cache()                         
{ 
    ::initCache(this);  // Somewhere is defined another initCache(), but I don't know where (it is not mine)
}

Cache::~Cache()                        
{ 
    for (auto ptr : *cache)
        delete ptr.second;
    delete cache; 
}

TEntryOrTTree *Cache::find(Netflow &n)
{
    unsigned short localPort = (n.getDir() == Directions::INBOUND ? n.getDstPort() : n.getSrcPort());
    auto iter = (*cache).find(localPort);
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
    unsigned short localPort = (newNetflow->getDir() == Directions::INBOUND 
                             ? newNetflow->getDstPort() 
                             : newNetflow->getSrcPort());
    auto iter = (*cache).find(localPort);
    if (iter != (*cache).end())
    {   // the netflow record either exists in the cache or there is a netflow with the same local port
        if (iter->second->isTree())
        {
            TEntryOrTTree *found = static_cast<TTree*>(iter->second)->find(*newEntry->getNetflowPtr());
            // If the same entry already exists
            if (found->isEntry()) 
                log(LogLevel::ERROR, "TTree::insert called two times with the same Netflow.");// TODO what to do?
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
                log(LogLevel::ERROR, "Cache::insert called two times with the same Netflow.");// TODO what to do?
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
        (*cache)[localPort] = newEntry;
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
        // TODO
    }
}

void Cache::print()
{
    cout << lastUpdate.time_since_epoch().count() << endl;

    for (auto m : *cache)
        m.second->print();
}
