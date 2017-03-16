/** 
 *  @file       cache.hpp
 *  @brief      Cache implementation header file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    02.03.2017 04:32
 *  Edited:     16.03.2017 04:16
 *  Version:    1.0.0
 *  @todo       secure TEntry::map with mutex
 */

#pragma once

#include <string>           //  string
#include <vector>           //  vector
#include <map>              //  map
#include <chrono>           //  seconds
#include <mutex>            //  mutex
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
using std::string;



/*!
 * @brief An enum representing type of a node in a tree
 */
enum class NodeType { 
    ENTRY, //!< Node is #TEntry class
    TREE   //!< Node is #TTree class
};
/*!
 * @brief An enum representing a level in which the node resides in a tree
 */
enum TreeLevel { 
    LOCAL_PORT  =0, //!< Level in which we compare local port
    PROTO       =1, //!< Level in which we compare layer 4 protocol
    LOCAL_IP    =2, //!< Level in which we compare local IP address
    REMOTE_IP   =3, //!< Level in which we compare remote IP address
    REMOTE_PORT =4  //!< Level in which we compare remote port
};

/*!
 * @brief Overloaded prefix increment operator for #TreeLevel enum
 */
inline TreeLevel& operator++( TreeLevel &l ) 
{
    if ( l == TreeLevel::REMOTE_PORT )
        l = static_cast<TreeLevel>(0);
    using IntType = typename std::underlying_type<TreeLevel>::type;
    l = static_cast<TreeLevel>( static_cast<IntType>(l) + 1 );
    return l;
}

/*!
 * @brief Overloaded postfix increment operator for #TreeLevel enum
 */
inline TreeLevel operator++( TreeLevel &t, int ) 
{
    TreeLevel result = t;
    ++t;
    return result;
}

/*!
 * @typedef CommonValue
 * @brief An union which stores a values which are compared at different levels
 */
typedef union {
    unsigned short port;  //!< Source or destination port
    void *ip;             //!< Source or destination IPv4 or IPv6 address
    unsigned char proto;  //!< Layer 4 protocol
} CommonValue;



/*!
 * @class TEntryOrTTree
 * @brief Base class which a decision tree (cache) is made from
 */
class TEntryOrTTree
{
protected:
    NodeType nt;                                //!< Type of the node
    TreeLevel level = TreeLevel::LOCAL_PORT;    //!< Level in the tree
public:
    /*!
     * @brief A virtual d'tor
     */
    virtual ~TEntryOrTTree()        {};
    /*!
     * @return  True if the node is TEntry, false otherwise
     */
    bool isEntry()                  { return nt == NodeType::ENTRY; }
    /*!
     * @return  True if the node is TTree, false otherwise
     */
    bool isTree()                   { return nt == NodeType::TREE; }
    /*!
     * @brief       Set method for #TEntryOrTTree::level
     * @param[in]   l    Level in the tree
     */
    void setLevel(TreeLevel l)      { level = l; }
    /*!
     * @brief   Increments stored tree level
     */
    void incLevel()                 { level++; }
    /*!
     * @brief   Get method for #TEntryOrTTree::level
     * @return  Level in the tree
     */
    TreeLevel getLevel()            { return level; }
    /*!
     * @brief       Compares values important at a specific #TreeLevel
     * @param[in]   n    Pointer to a Netflow class with netflow information
     * @return      Comparison result
     */
    virtual bool levelCompare(Netflow *n) =0;
};



/*!
 * @class TEntry
 * @brief Class with application name, its socket's inode and a pointer to Netflow class
 */
class TEntry : public TEntryOrTTree
{
    string appName;                 //!< Application name to which n belongs
    int inode;                      //!< Inode number of #Tentry::appname 's socket
    Netflow *n;                     //!< Pointer to a netflow information
public:
    /*!
     * @brief       Constructor that sets level to parameter l and 
     *               #TEntryOrTTree::nt to #NodeType::ENTRY
     * @param[in]   l   Level in the tree
     */
    TEntry(TreeLevel l)                     { level = l; nt = NodeType::ENTRY; }
    /*!
     * @brief   Default destructor that deletes n
     */
    ~TEntry()                               { delete n; }
    /*!
     * @brief       Set method for #TEntry::appName
     * @param[in]   name    Application name
     */
    void setAppName(string &name)           { appName.assign(name); }
    /*!
     * @brief   Get method for #TEntry::appName
     * @return  Application name
     */
    string const & getAppName()             { return appName; }
    /*!
     * @brief       Set method for #TEntry::inode
     * @param[in]   i   Inode number
     */
    void setInode(int i)                    { inode = i; }
    /*!
     * @brief   Get method for #TEntry::inode
     * @return  Inode number
     */
    int getInode()                          { return inode; }
    /*!
     * @brief       Set method for #TEntry::n
     * @pre         newNetflow must be a valid Netflow pointer
     * @post        Memory pointed by newNetflow must exist as long as TEntry object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   newNetflow  Pointer to new Netflow class
     */
    void setNetflowPtr(Netflow *newNetflow) { n = newNetflow; }
    /*!
     * @brief   Get method for #TEntry::n
     * @return  Pointer to Netflow class
     */
    Netflow * getNetflowPtr()               { return n; }
    /*!
     * @brief       Compares values important at a specific #TreeLevel
     * @param[in]   n1  Pointer to a Netflow class with netflow information
     * @return      Comparison result
     */
    bool levelCompare(Netflow *n1);
};



/*!
 * @class   TTree
 * @brief   Class with pointers to subtrees
 */
class TTree : public TEntryOrTTree
{
    unsigned char ipVersion;        //<! Version of IP header stored in #TTree::cv
    CommonValue cv;                 //<! Union which contains a value important ot node's level
    std::vector<TEntryOrTTree*> v;  //<! Vector of pointers to subtrees
public:
    /*!
     * @brief       Constructor that sets level to parameter l and 
     *              #TEntryOrTTree::nt to #NodeType::TREE
     * @param[in]   l   Level in the tree
     */
    TTree(TreeLevel l)                      { level = l; nt = NodeType::TREE; }
    /*!
     * @brief   Default d'tor that cycles through #TTree::v vector and frees used memory. 
     *          Then clears vector v.
     */
    ~TTree();
    /*!
     * @brief       Function finds a TEntry node with exact match or 
     *               a TTree node which contains TEntry with the closest match.
     * @details     TTree return value is used in #TTree::insert function. 
     *              Firstly we call #TTree::find and if it didn't find exact TEntry record
     *               it returns pointer to a TTree. 
     *              Then the new TEntry record is inserted into returned TTree node;
     * @param[in]   n   Reference to a Netflow class which the function looks for in the tree
     * @return      Pointer to a TEntry node in a case of the exact match, 
     *               otherwise pointer to a TTree node with a TEntry node with the closest match
     */
    TEntryOrTTree *find(Netflow &n);
    /*!
     * @brief       Function inserts new TEntry into a decision tree
     * @pre         entry must be a valid TEntry pointer
     * @post        Memory pointed by entry must exist as long as TTree object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   entry   Pointer to TEntry class to be inserted into a decision tree
     */
    void insert(TEntry *entry);
    /*!
     * @brief       Set method for #TTree::cv::port
     * @param[in]   p   Source or destination port which is common in this subtree
     */
    void setPort(unsigned short p)              { cv.port = p; }
    /*!
     * @brief       Set method for #TTree::cv::ip
     * @pre         Ip must be a valid in*_addr pointer
     * @post        Memory pointed by Ip must exist as long as TTree object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   Ip  Pointer to source or destination IPv4 or IPv6 header which is common in this subtree
     * @param[in]   ipV IP header version
     */
    void setIp(void *Ip, unsigned char ipV)     { ipVersion = ipV; cv.ip = Ip; }
    /*!
     * @brief       Set method for #TTree::cv::proto
     * @param[in]   p   Layer 4 protocol which is common in this subtree
     */
    void setProto(unsigned char p)              { cv.proto = p; }
    /*!
     * @brief       Set method for #TTree::cv union
     * @pre         n is a valid pointer
     * @param[in]   n   Pointer to Netflow class which contains netflow information
     */
    void setCommonValue(Netflow *n);
    /*!
     * @brief       Compares values important at a specific #TreeLevel
     * @param[in]   n1  Pointer to a Netflow class with netflow information
     * @return      Comparison result
     */
    bool levelCompare(Netflow *n);
};



/*!
 * @class Cache
 * Cache contains time of its last update end map of open local ports
 */
class Cache
{
    //! @brief  Time of last update
    clock_type::time_point lastUpdate = clock_type::now();
    //! @brief  Map of open local ports
    std::map<unsigned short,TEntryOrTTree*> *cache = new std::map<unsigned short,TEntryOrTTree*>;
public:
    /*!
     * @brief   Default c'tor that initialises Cache 
     */
    Cache();
    /*!
     * @brief   Default d'tor that cycles through cache and deletes objects stored in it.
     *          Then it deletes cache pointer.
     */
    ~Cache();
    /*!
     * @brief       Function finds a Netflow record in a cache
     * @param[in]   n   Reference to a Netflow class that will find in the cache.
     * @return      Pointer to a TEntry node in a case of the exact match, 
     *               pointer to a TTree node with a TEntry node with the closest match
     *               or a nullptr if there is no such local port record in the map.
     */
    TEntryOrTTree *find(Netflow &n);
    /*!
     * @brief       Function inserts new TEntry into cache
     * @pre         entry must be a valid TEntry pointer
     * @post        Memory pointed by entry must exist as long as Cache object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   entry   Pointer to TEntry class to be inserted into a decision tree
     */
    void insert(TEntry *e);
    /*!
     * @brief       Function cycles until #shouldStop is set and periodically updates cache
     */
    void periodicUpdate();
};
