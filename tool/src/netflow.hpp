/** 
 *  @file       netflow.hpp
 *  @brief      Netflow structure header file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:13
 *  Edited:     16.03.2017 06:41
 *  Version:    1.0.0
 */

#pragma once

#include <string>           //  string
#include <netinet/in.h>     //  in_addr, in6_addr
#include <arpa/inet.h>      //  inet_ntop()



extern const char * g_dev;

/*!
 * An enum representing packet flow direction
 */
enum class Directions { 
    OUTBOUND, //!< Outgoing packets
    INBOUND   //!< Incoming packets
};


/*!
 * @class Netflow
 * @brief Netflow class contains information about packet needed to uniquely determine
 * a netflow it belongs to.
 */
class Netflow
{
    Directions dir;                     //!< Packet direction
    unsigned char ipVersion;            //!< IP header version
    /*!
     * @brief   Pointer to a source IP structure
     * @details Type of the pointer is determined using #Netflow::ipVersion
     */
    void *srcIp = nullptr;
    /*!
     * @brief   Pointer to a destnation IP structure
     * @details Type of the pointer is determined using #Netflow::ipVersion
     */
    void *dstIp = nullptr;
    unsigned short srcPort;             //!< Source port
    unsigned short dstPort;             //!< Destination port
    unsigned char proto;                //!< Layer 4 protocol
    const char *interface = nullptr;    //!< Name of the device that was used to capture packets
    long startTime;                     //!< Time of the first packet which belongs to this netflow
    long endTime;                       //!< Time of the last packet which belongs to this netflow
public:
    /*!
     * @brief Defalut constructor that sets interface to #g_dev
     */
    Netflow(const char *intf) : interface(intf) {}
    /*!
     * @brief       Constructor that sets interface to the parameter
     * @param[in]   intf     Interface used to capture packets
     */
    Netflow() : interface(g_dev) {}
    /*!
     * @brief   Destructor cleans memory pointed by #Netflow::srcIP and #Netflow::dstIp pointers
     */
    ~Netflow();
    /*! 
     * @brief   Get method for #Netflow::dir
     * @return  Packet direction
     */
    Directions getDir()                     { return dir; }
    /*! 
     * @brief       Set method for #Netflow::dir
     * @param[in]   d         Packet direction
     */
    void setDir(Directions d)               { dir = d; }
    /*! 
     * @brief   Get method for #Netflow::ipVersion
     * @return  IP header version
     */
    unsigned char getIpVersion()            { return ipVersion; }
    /*! 
     * @brief       Set method for #Netflow::ipVersion
     * @param[in]   ipV       IP header version
     */
    void setIpVersion(unsigned char ipV)    { ipVersion = ipV; }
    /*! 
     * @brief   Get method for #Netflow::srcIp
     * @return  Pointer to source IP structure
     */
    void * getSrcIp()                       { return srcIp; }
    /*! 
     * @brief       Set method for #Netflow::srcIp
     * @pre         newIp must point to a valid in*_addr structure
     * @post        Memory pointed by newIp must exist as long as Netflow object exists.
     *              Then it will be freed in destructor.
     * @param[in]   newIp     Source IP structure pointer
     */
    void setSrcIp(void *newIp)              { srcIp = newIp; }
    /*! 
     * @brief   Get method for #Netflow::dstIp
     * @return  Pointer to destination IP structure
     */
    void * getDstIp()                       { return dstIp; }
    /*! 
     * @brief       Set method for #Netflow::dstIp
     * @pre         newIp must point to a valid in*_addr structure.
     * @post        Memory pointed by newIp must exist as long as Netflow object exists.
     *              Then it will be freed in destructor.
     * @param[in]   newIp     Destination IP structure pointer
     */
    void setDstIp(void *newIp)              { dstIp = newIp; }
    /*! 
     * @brief   Get method for #Netflow::srcPort
     * @return  Source port
     */
    unsigned short getSrcPort()             { return srcPort; }
    /*! 
     * @brief       Set method for #Netflow::srcPort
     * @param[in]   newPort   Source port
     */
    void setSrcPort(unsigned short newPort) { srcPort = newPort; }
    /*! 
     * @brief   Get method for #Netflow::dstPort
     * @return  Destination port
     */
    unsigned short getDstPort()             { return dstPort; }
    /*! 
     * @brief       Set method for #Netflow::dstPort
     * param[in]    newPort   Destination port
     */
    void setDstPort(unsigned short newPort) { dstPort = newPort; }
    /*! 
     * @brief   Get method for #Netflow::proto
     * @return  Layer 4 protocol
     */
    unsigned char getProto()                { return proto; }
    /*! 
     * @brief       Set method for #Netflow::proto
     * @param[in]   newProto  Layer 4 protocol
     */
    void setProto(unsigned char newProto)   { proto = newProto; }
    /*! 
     * @brief   Get method for #Netflow::interface
     * @return  Interface which was used to capture packets
     */
    const char *getInterface()              { return interface; }
    /*! 
     * @brief       Set method for #Netflow::interface
     * @param[in]   newInt    Interface which was used to capture packets
     */
    void setInterface(char *newInt)         { interface = newInt; }
    /*! 
     * @brief   Get method for #Netflow::startTime
     * @return  Time of the first packet which belongs to this netflow
     */
    int getStartTime()                      { return startTime; }
    /*! 
     * @brief       Set method for #Netflow::startTime
     * @param[in]   newTime   Time of the first packet which belongs to this netflow
     */
    void setStartTime(long newTime)         { startTime = newTime; }
    /*! 
     * @brief   Get method for #Netflow::endTime
     * @return  Time of the last packet which belongs to this netflow
     */
    int getEndTime()                        { return endTime; }
    /*! 
     * @brief       Set method for #Netflow::endTime
     * @param[in]   newTime   Time of the last packet which belongs to this netflow
     */
    void setEndTime(long newTime)           { endTime = newTime; }
    /*!
     * @brief   Overloaded equality operator
     * @details Compares just netflow relevant variables
     */
    bool operator==(const Netflow& other) const;
    /*!
     * @brief   Function prints content of the Netflow structure
     */
    void print();
};
