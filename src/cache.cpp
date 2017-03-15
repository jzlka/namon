/** 
 *  @file       cache.cpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:52
 *  Edited:     15.03.2017 02:03
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @todo       when inserting set levels in TTree and TEntry
 */

#include <iostream>             //  cout, endl;
#include <thread>               //  sleep_for
#include "netflow.hpp"          //  Netflow
#include "cache.hpp"            //  Cache

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


TEntryOrTTree * TTree::find(Netflow &n)
{
    for (auto ptr : v)
    {
        if (ptr->levelCompare(n))
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

void TTree::insert(TEntry &/*entry*/)
{

}

void TTree::insert(TEntry &/*oldEntry*/, TEntry &/*entry*/)
{

}


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


void Cache::insert(TEntry &newEntry)
{
    Netflow *newNetflow = newEntry.getNetflowPtr();
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
                static_cast<TTree*>(iter->second)->insert(*oldEntry, newEntry);
            }
        }
    }
    else
    {
        TEntry *newEntry = new TEntry;
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
