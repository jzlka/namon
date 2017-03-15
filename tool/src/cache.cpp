/** 
 *  @file       cache.cpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:52
 *  Edited:     15.03.2017 17:55
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @todo       when inserting set levels in TTree and TEntry
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
                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else
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
                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
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
                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else
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
                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
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




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
 *                                                                            *
 *                                  class TTree                               *
 *                                                                            *
 *++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
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
    TEntryOrTTree *found = find(*entry->getNetflowPtr());
    // If the same entry already exists
    if (found->isEntry()) 
        log(LogLevel::ERROR, "TTree::insert called two times with the same Netflow.");// TODO what to do?
    else
    {
        for (auto ptr : v)
        {
            if (ptr->isEntry() && ptr->levelCompare(entry->getNetflowPtr()))
            {
                TEntry *oldEntry = static_cast<TEntry*>(ptr);
                // Create a new tree
                ptr = new TTree(oldEntry->getLevel());
                // Set common value at that level
                static_cast<TTree*>(ptr)->setCommonValue(oldEntry->getNetflowPtr());
                // Insert an old entry with the new one
                static_cast<TTree*>(ptr)->insert(oldEntry);
                static_cast<TTree*>(ptr)->insert(entry);
                return;
            }
            // else if isTree() or it doesn't have same lvl value just ignore it
            // We ignore TTree because find returns TTree with the closest match
            // so we don't have to go deeplier in the tree.
        }
        // If there is no element with the same value on its level then add a new one
        // TODO create now one and copy or just insert?
        //TEntry *newEntry = new TEntry();
        //*newEntry = entry;
        entry->setLevel(found->getLevel());
        entry->incLevel();
        v.push_back(entry);
    }
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
        {
            if (n->getDir() == Directions::INBOUND)
                setIp(n->getDstIp());
            else
                setIp(n->getSrcIp());
            break;
        }
        case TreeLevel::REMOTE_IP:
        {
            if (n->getDir() == Directions::INBOUND)
                setIp(n->getSrcIp());
            else
                setIp(n->getDstIp());
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
            if (n->getIpVersion() == 4)
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
                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else
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
                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
        }
        case TreeLevel::REMOTE_IP:
        {
            if (n->getIpVersion() == 4)
            {
                in_addr *tmpPtr = static_cast<in_addr*>(cv.ip);
                in_addr *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                    tmpPtr2 = static_cast<in_addr*>(n->getSrcIp());
                else
                    tmpPtr2 = static_cast<in_addr*>(n->getDstIp());

                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in_addr));
            }
            else
            {
                in6_addr *tmpPtr = static_cast<in6_addr*>(cv.ip);
                in6_addr *tmpPtr2;
                if (n->getDir() == Directions::INBOUND)
                    tmpPtr2 = static_cast<in6_addr*>(n->getSrcIp());
                else
                    tmpPtr2 = static_cast<in6_addr*>(n->getDstIp());

                return memcmp(tmpPtr, tmpPtr2, sizeof(struct in6_addr));
            }
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




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*
 *                                                                            *
 *                                  class Cache                               *
 *                                                                            *
 *++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
TEntryOrTTree *Cache::find(Netflow &n)
{
    unsigned short localPort = (n.getDir() == Directions::INBOUND ? n.getDstPort() : n.getSrcPort());
    auto iter = (*cache).find(localPort);
    if (iter != (*cache).end())
    {   // the netflow record either exists in the cache or there is a netflow with the same local port
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
            static_cast<TTree*>(iter->second)->insert(newEntry);
        else    // isEntry -> record already exists
        {
            TEntry *oldEntry = static_cast<TEntry*>(iter->second);
            // If the same netflow record already exists, update endTime
            if (*(oldEntry->getNetflowPtr()) == *newNetflow)
                oldEntry->getNetflowPtr()->setEndTime(newNetflow->getEndTime());
            else
            {
                // Create a new tree
                iter->second = new TTree(oldEntry->getLevel());
                static_cast<TTree*>(iter->second)->setPort(oldEntry->getNetflowPtr()->getSrcPort());
                // Insert an old entry with the new one
                static_cast<TTree*>(iter->second)->insert(oldEntry);
                static_cast<TTree*>(iter->second)->insert(newEntry);
            }
        }
    }
    else
    {
        //TEntry *newEntry = new TEntry(TreeLevel::LOCAL_PORT);
        newEntry->setLevel(TreeLevel::LOCAL_PORT);
        (*cache)[localPort] = newEntry;
    }
}


void Cache::periodicUpdate()
{
    while(!shouldStop)
    {
        // If it has been already updated (e.g. because of cache miss) don't update it
        if(duration_cast<seconds>(clock_type::now()-lastUpdate) >= seconds(5))  
            this_thread::sleep_for(seconds(5));
        // If shoudStop was set during sleep
        if(!shouldStop)
            break;

        //map<unsigned short, TEntryOrTTree*> *newCache = new map<unsigned short, TEntryOrTTree*>;
        //::initCache(this);
        //diff();
    }
}
