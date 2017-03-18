/** 
 *  @file       fileHandler.hpp
 *  @brief      File handler header file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  @date
 *  - Created:  06.03.2017 14:50
 *  - Edited:       19.03.2017 00:11
 *  Version:    1.0.0
 */

#pragma once

#include <fstream>              //  ofstream
#include <vector>               //  vector
#include <atomic>               //  atomic
#include <mutex>                //  mutex
#include <thread>               //  thread()
#include <condition_variable>   //  condition_variable
#include <pcap.h>               //  pcap_pkthdr
#include "capturing.hpp"        //  stop()
#include "pcapng_blocks.hpp"    //  EnhancedPacketBlock


extern std::ofstream oFile;



/*!
 * @brief       Creates the output file and writes SectionHeaderBlock and InterfaceDescriptionBlock to the file
 * @param[in]   oFile   The output file
 */
void initOFile(std::ofstream & oFile);



/*!
 * @class   RingBuffer
 * @todo    translate /vyrovnat/ in the description
 * @brief   Class used to /vyrovnat/ speed difference between network interface and hard drive
 */
class RingBuffer
{
    //! @brief  Vector of EnhancedPacketBlock instances to store packets
    //!          which will be printed to #oFile
    std::vector<EnhancedPacketBlock> buffer ;
    //! @brief  First element of the ring buffer
    size_t first = 0 ;
    //! @brief  Last element of the ring buffer
    size_t last = 0 ;
    //! @brief  Number of elements in the ring buffer
    std::atomic_size_t size; // zero initialized by default

    //! @brief  Mutex used to lock #RingBuffer::m_condVar
    std::mutex m_mutex;
    //! @brief  Condition variable used to notify thread when a new packet is stored in the buffer
    std::condition_variable m_condVar;
    //! @brief  Defines if a new packet was saved to the buffer
    bool m_rcvdPacket = false;
public:
    /*!
     * @brief       Constructor with size as parameter
     * @param[in]   cap Capacity of the buffer
     */
    RingBuffer( size_t cap ) : buffer(cap) {}
    /*!
     * @return  True if the buffer is empty
     */
    bool empty() const      { return size == 0; }
    /*!
     * @return  True if the buffer is full
     */
    bool full() const       { return size == buffer.size(); }
    /*!
     * @brief   Function notify all threads to check #RingBuffer::m_condVar
     * @details Because #RingBuffer::m_condVar is private member of this class this method
     *           is used to notify threads from main.
     */
    void notifyCondVar()    { m_condVar.notify_all(); }
    /*!
     * @brief   Callback function that is called when m_condVar.notify_*() is called
     * @return  True if the thread should stop or a new packet is saved in the buffer
     */
    bool receivedPacket()   { return m_rcvdPacket || stop(); }
    /*!
     * @brief       Saves new packet into the buffer
     * @param[in]   header  libpcap header
     * @param[in]   packet  received packet
     * @return      False if packet was dropped. True otherwise.
     */
    int push(const pcap_pkthdr *header, const u_char *packet);
    /*!
     * @brief   Moves #RingBuffer::first to the next element
     */
    void pop();
    /*!
     * @brief   Writes whole buffer into the #oFile
     */
    void write();
};
