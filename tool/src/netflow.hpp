/** 
 *  @file       netflow.hpp
 *  @brief      Netflow structure header file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    26.02.2017 23:13
 *  Edited:     16.03.2017 00:42
 *  Version:    1.0.0
 */

#pragma once

#include <string>           //  string
#include <netinet/in.h>     //  in_addr, in6_addr



/*!
 * An enum representing packet flow direction
 */
enum class Directions { 
    OUTBOUND, //!< Outgoing packets
    INBOUND   //!< Incoming packets
};


/*!
 * @class Netflow
 * Netflow class contains information about packet needed to uniqely determine
 * a netflow it belongs to.
 */
class Netflow
{
    Directions dir;                     //!< Packet direction
    unsigned char ipVersion;            //!< IP header version
    /*!
     * Pointer to a source IP structure
     * Type of the pointer is determined using #Netflow::ipVersion
     */
    void *srcIp = nullptr;
    /*!
     * Pointer to a destnation IP structure
     * Type of the pointer is determined using #Netflow::ipVersion
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
     * Constructor
     * @param[in]  intf     Interface used to capture packets
     */
    Netflow(const char *intf);
    /*!
     * Constructor
     */
    Netflow();
    /*!
     * Destructor
     */
    ~Netflow();
    /*! Get method for #Netflow::dir
     * @return  Packet direction
     */
    Directions getDir();
    /*! Set method for #Netflow::dir
     * param[in]  d         Packet direction
     */
    void setDir(Directions d);
    /*! Get method for #Netflow::ipVersion
     * return  IP header version
     */
    unsigned char getIpVersion();
    /*! Set method for #Netflow::ipVersion
     * param[in]  ipV       IP header version
     */
    void setIpVersion(unsigned char ipV);
    /*! Get method for #Netflow::srcIp
     * return  Pointer to source IP structure
     */
    void *getSrcIp();
    /*! Set method for #Netflow::srcIp
     * @pre  newIp must point to a valid in*_addr structure
     * @post Memory pointed by newIp must exist as long as Netflow object exists.
     *       Then it will be freed in destructor.
     * param[in]  newIp     Source IP structure pointer
     */
    void setSrcIp(void *newIp);
    /*! Get method for #Netflow::dstIp
     * return  Pointer to destination IP structure
     */
    void *getDstIp();
    /*! Set method for #Netflow::dstIp
     * @pre  newIp must point to a valid in*_addr structure.
     * @post Memory pointed by newIp must exist as long as Netflow object exists.
     *       Then it will be freed in destructor.
     * param[in]  newIp     Destination IP structure pointer
     */
    void setDstIp(void *newIp);
    /*! Get method for #Netflow::srcPort
     * return  Source port
     */
    unsigned short getSrcPort();
    /*! Set method for #Netflow::srcPort
     * param[in]  newPort   Source port
     */
    void setSrcPort(unsigned short newPort);
    /*! Get method for #Netflow::dstPort
     * return  Destination port
     */
    unsigned short getDstPort();
    /*! Set method for #Netflow::dstPort
     * param[in]  newPort   Destination port
     */
    void setDstPort(unsigned short newPort);
    /*! Get method for #Netflow::proto
     * return  Layer 4 protocol
     */
    unsigned char getProto();
    /*! Set method for #Netflow::proto
     * param[in]  newProto  Layer 4 protocol
     */
    void setProto(unsigned char newProto);
    /*! Get method for #Netflow::interface
     * return  Interface which was used to capture packets
     */
    const char *getInterface();
    /*! Set method for #Netflow::interface
     * param[in]  newInt    Interface which was used to capture packets
     */
    void setInterface(char *newInt);
    /*! Get method for #Netflow::startTime
     * return  Time of the first packet which belongs to this netflow
     */
    int getStartTime();
    /*! Set method for #Netflow::startTime
     * param[in]  newTime   Time of the first packet which belongs to this netflow
     */
    void setStartTime(long newTime);
    /*! Get method for #Netflow::endTime
     * return  Time of the last packet which belongs to this netflow
     */
    int getEndTime();
    /*! Set method for #Netflow::endTime
     * param[in]  newTime   Time of the last packet which belongs to this netflow
     */
    void setEndTime(long newTime);
    /*!
     * Overloaded equality opretor
     */
    bool operator==(const Netflow& other) const;
};
