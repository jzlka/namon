/** 
 *  @file       cache.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    02.03.2017 04:32
 *  Edited:     15.03.2017 02:03
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @todo       secure TEntry::map with mutex
 */

#pragma once

#include <string>           //  string
#include <vector>           //  vector
#include <map>              //  map
#include <chrono>           //  seconds
#include "netflow.hpp"      //  Netflow

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



using clock_type = std::chrono::high_resolution_clock;


//auto lvlCompareTEntry = { 
//        [n](Netflow &nToFind){ return n->getSrcPort() == nToFind.getSrcPort(); }, };
//lvlCompareTEntry


enum class NodeType { ENTRY, TREE };

class TEntryOrTTree
{
protected:
    NodeType nt;
    unsigned char level = 0;
public:
    bool isEntry()                  { return nt == NodeType::ENTRY; }
    bool isTree()                   { return nt == NodeType::TREE; }
    void setLevel(unsigned char l)  { level = l; }
    unsigned char getLevel()        { return level; }
    bool (*levelCompare)(Netflow &n) = nullptr;
};


class TEntry : public TEntryOrTTree
{
    std::string appName;
    int inode;
    Netflow *n;
public:
    TEntry(unsigned char l=0)       { level = l; nt = NodeType::ENTRY; }
    std::string &getAppName()       { return appName; }
    void setInode(int i)            { inode = i; }
    int getInode()                  { return inode; }
    Netflow *getNetflowPtr()        { return n; }
};


class TTree : public TEntryOrTTree
{
    union {
        unsigned short port;
        in_addr *ip;
        in6_addr *ip6;
        unsigned char proto;
    } commonValue;
    std::vector<TEntryOrTTree*> v;
public:
    TTree(unsigned char l)          { level = l; nt = NodeType::TREE; }
    TEntryOrTTree *find(Netflow &n);
    void insert(TEntry &entry);
    void insert(TEntry &oldEntry, TEntry &entry);
    void setPort(unsigned short p)  { commonValue.port = p; }
    void setIp(in_addr *Ip)         { commonValue.ip = Ip; }
    void setIp6(in6_addr *Ip6)      { commonValue.ip6 = Ip6; }
    void setProto(unsigned char p)  { commonValue.proto = p; }
};


class Cache
{
    clock_type::time_point lastUpdate = clock_type::now();
    std::map<unsigned short,TEntryOrTTree*> *cache = new std::map<unsigned short,TEntryOrTTree*>;
public:
    Cache()                         { ::initCache(this); lastUpdate = clock_type::now(); }
    ~Cache()                        { delete cache; }
    TEntryOrTTree *find(Netflow &n);
    void insert(TEntry &e);
    void periodicUpdate();
};
