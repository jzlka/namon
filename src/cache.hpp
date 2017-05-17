/** 
 *  @file       cache.hpp
 *  @brief      Cache implementation header file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 02.03.2017 04:32
 *   - Edited:  18.05.2017 00:22
 */

#pragma once

#include <string>           //  string
#include <vector>           //  vector
#include <unordered_map>    //  map
#include <chrono>           //  seconds

#include "netflow.hpp"      //  Netflow

using clock_type = std::chrono::high_resolution_clock;
using std::string;
using std::chrono::seconds;
using std::chrono::duration_cast;




namespace TOOL
{


extern const int VALID_TIME;


/*!
 * @brief An enum representing type of node in a tree
 */
enum class NodeType { 
    ENTRY, //!< Node is #TEntry class
    TREE   //!< Node is #TTree class
};

/*!
 * @brief An enum representing a level in which the node resides in a tree
 */
enum class TreeLevel { 
    LOCAL_PORT  =0, //!< Level in which we compare local port
    PROTO       =1, //!< Level in which we compare layer 4 protocol
    LOCAL_IP    =2, //!< Level in which we compare local IP address
};

/*!
 * @brief Overloaded prefix increment operator for #TOOL::TreeLevel enum
 */
inline TreeLevel& operator++( TreeLevel &l ) 
{
    if ( l == TreeLevel::LOCAL_IP )
        l = static_cast<TreeLevel>(0);
    using IntType = typename std::underlying_type<TreeLevel>::type;
    l = static_cast<TreeLevel>( static_cast<IntType>(l) + 1 );
    return l;
}

/*!
 * @brief Overloaded postfix increment operator for #TOOL::TreeLevel enum
 */
inline TreeLevel operator++( TreeLevel &t, int ) 
{
    TreeLevel result = t;
    ++t;
    return result;
}

/*!
 * @brief Overloaded prefix increment operator for #TOOL::TreeLevel enum
 */
inline TreeLevel operator+( TreeLevel &l, int a ) 
{
    TreeLevel result;
    using IntType = typename std::underlying_type<TreeLevel>::type;
    result = static_cast<TreeLevel>( static_cast<IntType>(l) + a );
    if ( result > TreeLevel::LOCAL_IP )
        result = static_cast<TreeLevel>(0);
    return result;
}

/*!
 * @union CommonValue
 * @brief An union which stores values which are compared at different levels
 */
typedef union {
    unsigned short port;    //!< Local port
    void *ip =nullptr;      //!< Local IPv4 or IPv6 address
    unsigned char proto;    //!< Layer 4 protocol
} CommonValue;



/*!
 * @class TEntryOrTTree
 * @brief Base class which a decision tree (cache) is made of
 */
class TEntryOrTTree
{
protected:
    NodeType nt;                                //!< Type of the node
    TreeLevel level = TreeLevel::LOCAL_PORT;    //!< Level in the tree
public:
    /*!
     * @brief   A virtual d'tor
     */
    virtual ~TEntryOrTTree()        {};
    /*!
     * @return  Returns true if the node is TEntry, false otherwise
     */
    bool isEntry()                  { return nt == NodeType::ENTRY; }
    /*!
     * @return  True if the node is TTree, false otherwise
     */
    bool isTree()                   { return nt == NodeType::TREE; }
    /*!
     * @brief       Set method for #TOOL::TEntryOrTTree::level
     * @param[in]   l    Level in the tree
     */
    void setLevel(TreeLevel l)      { level = l; }
    /*!
     * @brief   Increments actual tree level
     */
    void incLevel()                 { level++; }
    /*!
     * @brief   Get method for #TOOL::TEntryOrTTree::level
     * @return  Level in the tree
     */
    TreeLevel getLevel()            { return level; }
    /*!
     * @brief       Compares values important at a specific #TOOL::TreeLevel
     * @param[in]   n    Pointer to a Netflow class with netflow information
     * @return      Returns true if *this and n parameter have same value on their level. False otherwise
     */
    virtual bool levelCompare(Netflow *n) =0;
    /*!
     * @brief   Function prints content of the class to the standard output
     */
    virtual void print() =0;
};



/*!
 * @class TEntry
 * @brief Class with application name, its socket inode (Linux) or PID (windows) and a pointer to Netflow class
 */
class TEntry : public TEntryOrTTree
{
    //! @brief  Time of last update
    clock_type::time_point lastUpdate = clock_type::now();
    string appName ="";             //!< Application name which #TOOL::TEntry::n belongs to
    int inodeOrPid =0;                   //!< Inode number of #TOOL::TEntry::appName 's socket
    Netflow *n = nullptr;           //!< Pointer to a netflow record
public:
    /*!
     * @brief   Default constructor that sets node type to #NodeType::ENTRY
     */
    TEntry()                                { nt = NodeType::ENTRY; }
    /*!
     * @brief       Constructor that sets level to parameter l and 
     *              #TOOL::TEntryOrTTree::nt to #NodeType::ENTRY
     * @param[in]   l   Level in the tree
     */
    TEntry(TreeLevel l)                     { level = l; nt = NodeType::ENTRY; }
    /*!
     * @brief   Default destructor that deletes #TOOL::TEntry::n
     */
    ~TEntry()                               { delete n; }
    /*!
     * @brief   Updates #TOOL::TEntry::lastUpdate time with actual time
     */
    void updateTime()                       { lastUpdate = clock_type::now(); }
    /*!
     * @brief   Returns if this TEntry is still valid
     * @return  False if the entry is older or equal to #TOOL::VALID_TIME, true otherwise.
     */
    bool valid()     { return duration_cast<seconds>(clock_type::now()-lastUpdate) < seconds(VALID_TIME); }
    /*!
     * @brief       Set method for #TOOL::TEntry::appName
     * @param[in]   name    New application name
     */
    void setAppName(const string &name)     { appName = name; }
    /*!
     * @brief   Get method for #TOOL::TEntry::appName
     * @return  Application name
     */
    string const & getAppName()             { return appName; }
    /*!
     * @brief       Set method for #TOOL::TEntry::inodeOrPid
     * @param[in]   i   New inode (Linux) or PID (Win) number
     */
    void setInodeOrPid(int i)                    { inodeOrPid = i; }
    /*!
     * @brief   Get method for #TOOL::TEntry::inodeOrPid
     * @return  Inode number (Linux) or PID (Win)
     */
    int getInodeOrPid()                          { return inodeOrPid; }
    /*!
     * @brief       Set method for #TOOL::TEntry::n
     * @pre         newNetflow must be a valid Netflow pointer
     * @post        Memory pointed by newNetflow must exist as long as TEntry object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   newNetflow  Pointer to new Netflow class
     */
    void setNetflowPtr(Netflow *newNetflow) { n = newNetflow; }
    /*!
     * @brief   Get method for #TOOL::TEntry::n
     * @return  Pointer to a Netflow class
     */
    Netflow * getNetflowPtr()               { return n; }
    /*!
     * @brief       Compares values important at a specific #TOOL::TreeLevel
     * @param[in]   n1  Pointer to a Netflow class with netflow information
     * @return      True if *this and n have same level values
     */
    bool levelCompare(Netflow *n1);
    /*!
     * @brief   Function prints content of the class to the standard output
     */
    void print();
    /*!
     * @brief   Overloaded copy assignment operator
     * @details If #TOOL::TEntry::n is NULL, it allocates new memory for new Netflow.
     */
    TEntry& operator=(const TEntry& other)
    {
        if (this != &other)
        {
            lastUpdate = other.lastUpdate;
            appName = other.appName;
            inodeOrPid = other.inodeOrPid;
            if (n == nullptr)
                n = new Netflow;
            *n = *other.n;
        }
        return *this;
    }
    /*!
     * @brief   Overloaded move assignment operator
     * @details It dealocates old #TOOL::TEntry::n and sets pointer to new Netflow
     */
    TEntry& operator=(TEntry&& other)
    {
        if (this != &other)
        {
            lastUpdate = other.lastUpdate;
            appName = other.appName;
            inodeOrPid = other.inodeOrPid;
            delete n;
            n = other.n;
            
            other.lastUpdate = clock_type::now();
            other.appName = "";
            other.inodeOrPid = 0;
            other.n = nullptr;
        }
        return *this;
    }
};



/*!
 * @class   TTree
 * @brief   Class with pointers to subtrees
 */
class TTree : public TEntryOrTTree
{
    unsigned char ipVersion;        //!< Version of IP header stored in #TOOL::TTree::cv in case of LOCAL_IP #TOOL::TreeLevel
    CommonValue cv;                 //!< Union which contains a value important at node's #TOOL::TreeLevel
    std::vector<TEntryOrTTree*> v;  //!< Vector of pointers to subtrees
public:
    /*!
     * @brief       Constructor that sets level to parameter l and 
     *              #TOOL::TEntryOrTTree::nt to #NodeType::TREE
     * @param[in]   l   Level in the tree
     */
    TTree(TreeLevel l)                      { level = l; nt = NodeType::TREE; }
    /*!
     * @brief   Default d'tor that cycles through #TOOL::TTree::v vector and frees used memory. 
     *          Then clears the vector #TTree:v itself.
     */
    ~TTree();
    /*!
     * @brief       Function finds a TEntry node with exact match or a TTree node with the nearest match.
     * @param[in]   n   Reference to a Netflow class in the tree which the function looks for.
     * @return      Pointer to a TEntry node in a case of the exact match, 
     *              otherwise pointer to a TTree node with the closest match
     */
    TEntryOrTTree *find(Netflow &n);
    /*!
     * @brief       Function inserts a new TEntry into a decision tree
     * @pre         'entry' must be a valid TEntry pointer
     * @post        Memory pointed by 'entry' must exist as long as TTree object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   entry   Pointer to TEntry class to be inserted into a decision tree
     */
    void insert(TEntry *entry);
    /*!
     * @brief       Set method for #TOOL::TTree::cv
     * @param[in]   p   Local port which is common in this subtree
     */
    void setPort(unsigned short p)              { cv.port = p; }
    /*!
     * @brief       Set method for #TOOL::TTree::cv
     * @pre         Ip must be a valid in*_addr pointer
     * @post        Memory pointed by Ip must exist as long as TTree object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   Ip  Pointer to local IPv4 or IPv6 header which is common in this subtree
     * @param[in]   ipV IP header version
     */
    void setIp(void *Ip, unsigned char ipV)     { ipVersion = ipV; cv.ip = Ip; }
    /*!
     * @brief       Set method for #TOOL::TTree::cv
     * @param[in]   p   Layer 4 protocol which is common in this subtree
     */
    void setProto(unsigned char p)              { cv.proto = p; }
    /*!
     * @brief       Set method for #TOOL::TTree::cv union
     * @warning     If the method is called two times in one instance for the same level, memory leak will occur
     * @pre         'n' is a valid pointer
     * @param[in]   n   Pointer to Netflow class which contains netflow information
     */
    void setCommonValue(Netflow *n);
    /*!
     * @brief       Compares values important at a specific #TOOL::TreeLevel
     * @param[in]   n   Pointer to a Netflow class with netflow information
     * @return      Comparison result
     */
    bool levelCompare(Netflow *n);
    /*!
     * @brief   Finds invalid entries and saves them in #g_finalResults
     * @warning After this call, there are zero initialized netflow records in cache
     */
    void saveResults();
    /*!
     * @brief   Function prints content of the class to the standard output
     */
    void print();
};



/*!
 * @class Cache
 * Cache contains map of open local ports
 */
class Cache
{
    //! @brief  Map of open local ports
    std::unordered_map<unsigned short,class TEntryOrTTree*> *map = new std::unordered_map<unsigned short,class TEntryOrTTree*>;
public:
    /*!
     * @brief   Default c'tor that initialises Cache 
     */
    Cache() {}
    /*!
     * @brief   Default d'tor that cycles through cache and deletes objects stored in it.
     *          Then it deletes cache pointer itself.
     */
    ~Cache();
    /*!
     * @brief       Set method for #TOOL::Cache::map
     * @param[in]   newMap  Pointer to a new actualized map
     */
    void setCache(std::unordered_map<unsigned short,TEntryOrTTree*> *newMap) { map = newMap; }
    /*!
     * @brief       Function finds a Netflow record in a cache
     * @param[in]   n   Reference to a Netflow class, it tries to find in the cache.
     * @return      Pointer to a TEntry node in a case of the exact match, 
     *              pointer to a TTree node with the closest match
     *              or a nullptr if there is not exactly the same record in the map.
     */
    TEntryOrTTree *find(Netflow &n);
    /*!
     * @brief       Function inserts new TEntry into the TTree node
     * @pre         'e' must be a valid TEntry pointer
     * @post        Memory pointed by 'e' must exist as long as Cache object exists.
     *              Then it will be freed in a destructor.
     * @param[in]   e   Pointer to TEntry class to be inserted into a decision tree
     */
    void insert(TEntry *e);
    /*!
     * @brief   Finds expired entries and saves them in #g_finalResults
     * @warning Cache will contain zero initialized (moved) entries after this call.
     *          It is supposed to be called at the end of the program runtime.
     */
    void saveResults();
    /*!
     * @brief   Function prints content of the class to the standard output
     */
    void print();
};


}	// namespace TOOL
