/** 
 *  @file       ringBuffer.tpp
 *  @brief      Ring Buffer template functions
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    22.03.2017 17:04
 *  Edited:     24.03.2017 12:49
 *  Version:    1.0.0
 */

#if defined(__linux__)
#include "tool_linux.hpp"
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


template <class EnhancedPacketBlock>
int RingBuffer<EnhancedPacketBlock>::push(const pcap_pkthdr *header, const u_char *packet)
{
    if (full()) 
    {
        log(LogLevel::WARNING, "Packet dropped!");
        droppedElem++;
        return 1;
    }

    if (last >= buffer.size()) 
        last = 0;
    buffer[last].setCapturedPacketLength(header->caplen);
    buffer[last].setOriginalPacketLength(header->len);
    buffer[last].setTimestamp(header->ts.tv_usec); //! @todo    Will usec be precise enough?
    buffer[last].setPacketData(packet);
    ++last;
    ++size;

    std::lock_guard<std::mutex> guard(m_mutex);
    m_newItem = true;
    m_condVar.notify_all();
    return 0;
}


template <class T>
int RingBuffer<T>::push(T *n)
{
    if (full()) 
    {
        log(LogLevel::WARNING, "Packet dropped!");
        droppedElem++;
        return 1;
    }

    if (last >= buffer.size()) 
        last = 0;
    buffer[last] = *n;
    ++last;
    ++size;

    std::lock_guard<std::mutex> guard(m_mutex);
    m_newItem = true;
    m_condVar.notify_all();
    return 0;
}


template<class T>
void RingBuffer<T>::pop()
{
    first = (first+1) % buffer.size() ;
    --size;
    if (empty())
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_newItem = false;
    }
}


template<class EnhancedPacketBlock>
void RingBuffer<EnhancedPacketBlock>::write(ofstream &file)
{
    log(LogLevel::INFO, "Writing to the output file started.");
    while (!stop())
    {
        std::unique_lock<std::mutex> mlock(m_mutex);
        m_condVar.wait(mlock, std::bind(&RingBuffer::newItemOrStop, this));
        mlock.unlock();
        while(!empty())
        {
            buffer[first].write(file); //! @todo   mutex needed
            pop();
        }
    }
    log(LogLevel::INFO, "Writing to the output file stopped.");
}


template<class Netflow>
void RingBuffer<Netflow>::run(Cache *c)
{
    while (!stop())
    {
        std::unique_lock<std::mutex> mlock(m_mutex);
        m_condVar.wait(mlock, std::bind(&RingBuffer::newItemOrStop, this));
        mlock.unlock();
        while(!empty())
        {
            TEntryOrTTree *cacheRecord = c->find(buffer[first]);
            if (cacheRecord != nullptr && cacheRecord->isEntry())
            {
                static_cast<TEntry *>(cacheRecord)->getNetflowPtr()->setEndTime(buffer[first].getEndTime());
                //! @todo check if the record is not expired
            }
            else    // either TTree or it is not in the map
            {
                //TEntry *e = determineApp(&buffer[first]);
                //c->insert(e); //! @todo uncomment
            }
            pop();
        }
    }
}
