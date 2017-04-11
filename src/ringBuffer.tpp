/** 
 *  @file       ringBuffer.tpp
 *  @brief      Ring Buffer template functions
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 22.03.2017 17:04
 *   - Edited:  11.04.2017 00:12
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
        droppedElem++;
        return 1;
    }

    if (last >= buffer.size()) 
        last = 0;

    buffer[last].setOriginalPacketLength(header->len);
    buffer[last].setTimestamp(header->ts.tv_usec); //! @todo    Will usec be precise enough?
    buffer[last].setPacketData(packet, header->caplen);
    ++last;
    ++size;

    cv_condVar.notify_all();
    return 0;
}


template <class T>
int RingBuffer<T>::push(T &elem)
{
    if (full()) 
    {
        droppedElem++;
        return 1;
    }

    //! @todo ked prepisujeme novy prvok tak dealokovat alokovanu pamat v starom prvku (ip v netflow)
    if (last >= buffer.size()) 
        last = 0;
    buffer[last] = move(elem);
    ++last;
    ++size;

    cv_condVar.notify_all();
    return 0;
}


template<class T>
void RingBuffer<T>::pop()
{
    first = (first+1) % buffer.size() ;
    --size;
}


template<class EnhancedPacketBlock>
void RingBuffer<EnhancedPacketBlock>::write(ofstream &file)
{
    log(LogLevel::INFO, "Writing to the output file started.");
    while (!shouldStop)
    {
        std::unique_lock<std::mutex> mlock(m_condVar);
        cv_condVar.wait(mlock, std::bind(&RingBuffer::newItemOrStop, this));
        mlock.unlock();
        while(!empty())
        {
            buffer[first].write(file);
            pop();
        }
        file.flush();
    if (file.bad()) // e.g. out of space
    {
        log(LogLevel::ERROR, "Output error.");
            throw "Output file error"; //! @todo catch it
        }
    }
    log(LogLevel::INFO, "Writing to the output file stopped.");
}


template<class Netflow>
void RingBuffer<Netflow>::run(Cache *cache)
{
    while (!shouldStop)
    {
        std::unique_lock<std::mutex> mlock(m_condVar);
        cv_condVar.wait(mlock, std::bind(&RingBuffer::newItemOrStop, this));
        mlock.unlock();
        while(!empty())
        {
            TEntryOrTTree *cacheRecord = cache->find(buffer[first]);
            // if we found some TEntry, check if it still valid
            if (cacheRecord != nullptr && cacheRecord->isEntry())
            {
                TEntry *foundEntry = static_cast<TEntry *>(cacheRecord);
                // If the record exists but is invalid, run determineApp() in update mode
                // to find new application, else update endTime.
                if (!foundEntry->valid())
                    determineApp(&buffer[first], *foundEntry, UPDATE);
                else
                    foundEntry->getNetflowPtr()->setEndTime(buffer[first].getEndTime());
            }
            else 
            { // else it is either TTree or it is not in the whole map (nullptr)
              // (both means it's not in the cache at all)
                TEntry *e = new TEntry;
                // If an error occured (can't open procfs file, etc.)
                if (!determineApp(&buffer[first], *e, FIND))
                {
                    // insert new record into map
                    if (cacheRecord == nullptr)
                        cache->insert(e);
                    else // else insert it into subtree
                        static_cast<TTree *>(cacheRecord)->insert(e);
                }
                else
                    delete e;
            }
            pop();
        }
    }
    log(LogLevel::INFO, "Caching stopped.");
}
