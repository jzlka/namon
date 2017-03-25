/** 
 *  @file       ringBuffer.hpp
 *  @brief      Ring Buffer header file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    22.03.2017 17:04
 *  Edited:     25.03.2017 19:58
 *  Version:    1.0.0
 */

#pragma once

#include <vector>               //  vector
#include <atomic>               //  atomic
#include <mutex>                //  mutex
#include <thread>               //  thread()
#include <condition_variable>   //  condition_variable
#include <pcap.h>               //  pcap_pkthdr
#include "pcapng_blocks.hpp"    //  EnhancedPacketBlock

extern std::atomic<int> shouldStop;


/*!
 * @class   RingBuffer
 * @brief   Class used to mask speed difference between network interface and hard drive
 */
template <class T>
class RingBuffer
{
    //! @brief  Vector of T instances to store packets
    //!          which will be printed to #oFile
    std::vector<T> buffer ;
    //! @brief  First element of the ring buffer
    size_t first = 0 ;
    //! @brief  Last element of the ring buffer
    size_t last = 0 ;
    //! @brief  Number of elements in the ring buffer
    std::atomic_size_t size {0};    // zero initialized by default (not on Linux !!!)
    //! @brief  Number of dropped elements
    unsigned int droppedElem = 0;

    //! @brief  Mutex used to lock #RingBuffer::m_condVar
    std::mutex m_condVar;
    //! @brief  Condition variable used to notify thread when a new packet is stored in the buffer
    std::condition_variable cv_condVar;
public:
    /*!
     * @brief       Constructor with size as parameter
     * @param[in]   cap Capacity of the buffer
     */
    RingBuffer( size_t cap ) : buffer(cap) {}
    /*!
     * @return  True if the buffer is empty
     */
    bool empty() const              { return size == 0; }
    /*!
     * @return  True if the buffer is full
     */
    bool full() const               { return size == buffer.size(); }
    /*!
     * @brief   Get method for #RingBuffer::droppedElem
     * @return  Number of dropped elements
     */
    unsigned int getDroppedElem()   { return droppedElem; }
    /*!
     * @brief       Saves new structure into the buffer
     * @param[in]   elem     Pointer to new element to push
     * @return      False if packet was dropped. True otherwise.
     */
    int push(T &elem);
    int push(const pcap_pkthdr *header, const u_char *packet);
    /*!
     * @brief   Moves #RingBuffer::first to the next element
     */
    void pop();
    /*!
     * @return  Reference to last inserted element in the buffer
     */
    T & top()                       { return buffer[last-1]; }
    /*!
     * @brief   Function notify all threads to check #RingBuffer::m_condVar
     * @details Because #RingBuffer::m_condVar is private member of this class this method
     *           is used to notify threads from main.
     */
    void notifyCondVar()            { cv_condVar.notify_all(); }
    /*!
     * @brief   Callback function that is called when m_condVar.notify_*() is called
     * @return  True if the thread should stop or a new packet is saved into the buffer
     */
    bool newItemOrStop()            { return !empty() || shouldStop; }
    /*!
     * @brief       Writes whole buffer into the #oFile
     * @param[in]   file    The output file
     */
    void write(ofstream &file);
    /*!
     * @brief       Runs searching received packets in cache and determining applications for them
     * @param[out]  c Cache which will be fileld
     */
    void run(Cache *c);
};

#include "ringBuffer.tpp"   //  class members
