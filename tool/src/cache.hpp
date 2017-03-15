/** 
 *  @file       cache.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    02.03.2017 04:32
 *  Edited:     15.03.2017 18:21
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



enum class NodeType { ENTRY, TREE };
enum TreeLevel { LOCAL_PORT=0, PROTO=1, LOCAL_IP=2, REMOTE_IP=3, REMOTE_PORT=4};

// ++TreeLevel
inline TreeLevel& operator++( TreeLevel &l ) 
{
    if ( l == TreeLevel::REMOTE_PORT )
        l = static_cast<TreeLevel>(0);
    using IntType = typename std::underlying_type<TreeLevel>::type;
    l = static_cast<TreeLevel>( static_cast<IntType>(l) + 1 );
    return l;
}

// TreeLevel++
inline TreeLevel operator++( TreeLevel &t, int ) 
{
    TreeLevel result = t;
    ++t;
    return result;
}


typedef union {
    unsigned short port;
    void *ip;
    unsigned char proto;
} CommonValue;




class TEntryOrTTree
{
protected:
    NodeType nt;
    TreeLevel level = TreeLevel::LOCAL_PORT;
public:
    virtual ~TEntryOrTTree()        {}
    bool isEntry()                  { return nt == NodeType::ENTRY; }
    bool isTree()                   { return nt == NodeType::TREE; }
    void setLevel(TreeLevel l)      { level = l; }
    void incLevel()                 { level++; }
    //void decLevel()                 { level--; }
    TreeLevel getLevel()            { return level; }
    virtual bool levelCompare(Netflow *n) =0;
};


class TEntry : public TEntryOrTTree
{
    std::string appName;
    int inode;
    Netflow *n;
public:
    TEntry()                        { nt = NodeType::ENTRY; }
    TEntry(TreeLevel l)             { level = l; nt = NodeType::ENTRY; }
    void setString()                { /* TODO */ }
    std::string &getAppName()       { return appName; }
    void setInode(int i)            { inode = i; }
    int getInode()                  { return inode; }
    Netflow *getNetflowPtr()        { return n; }
    bool levelCompare(Netflow *n1);
};


class TTree : public TEntryOrTTree
{
    CommonValue cv;
    std::vector<TEntryOrTTree*> v;
public:
    TTree(TreeLevel l)              { level = l; nt = NodeType::TREE; }
    ~TTree()                        { for (auto ptr : v) { delete ptr; } v.clear(); }
    TEntryOrTTree *find(Netflow &n);
    void insert(TEntry *entry);
    void insert(TEntry *oldEntry, TEntry *entry);
    void setPort(unsigned short p)  { cv.port = p; }
    void setIp(void *Ip)         { cv.ip = Ip; }
    void setProto(unsigned char p)  { cv.proto = p; }
    void setCommonValue(Netflow *n);
    bool levelCompare(Netflow *n);
};


class Cache
{
    clock_type::time_point lastUpdate = clock_type::now();
    std::map<unsigned short,TEntryOrTTree*> *cache = new std::map<unsigned short,TEntryOrTTree*>;
public:
    Cache()                         { ::initCache(this); lastUpdate = clock_type::now(); }
    ~Cache()                        { delete cache; }
    TEntryOrTTree *find(Netflow &n);
    void insert(TEntry *e);
    void periodicUpdate();
};
