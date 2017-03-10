/** 
 *  @file       fileHandler.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    06.03.2017 14:50
 *  Edited:     10.03.2017 14:20
 *  Version:    1.0.0
 *  g++:        Apple LLVM version 8.0.0 (clang-800.0.42.1)
 *  @bug
 *  @todo
 */

#pragma once

#include <fstream>              //  ofstream
#include <vector>               //  vector
#include <atomic>               //  atomic
#include <mutex>                //  mutex
#include <thread>               //  thread()
#include <condition_variable>   //  condition_variable
#include <pcap.h>               //  pcap_pkthdr
#include "main.hpp"             //  stop()
#include "pcapng_blocks.hpp"    //  EnhancedPacketBlock
#include "debug.hpp"            //  D(), log()

void initOFile(std::ofstream & oFile);

extern std::ofstream oFile;

class RingBuffer
{
    std::vector<EnhancedPacketBlock> buffer ;
    size_t first = 0 ;
    size_t last = 0 ;
    std::atomic_size_t size; // zero initialized by default

    std::mutex m_mutex;
    std::condition_variable m_condVar;
    bool m_rcvdPacket = false;
public:
    RingBuffer( size_t cap ) : buffer(cap) {}
    bool empty() const { return size == 0; }
    bool full() const { return size == buffer.size(); }
    bool receivedPacket() { D("checking var"); return m_rcvdPacket || stop(); }

    void push(const pcap_pkthdr *header, const u_char *packet)
    {
        if (full()) 
        {
            log(LogLevel::WARNING, "Packet dropped!");
            return;
        }
        else
            ++size;

        if (last >= buffer.size()) 
            last = 0;
        buffer[last].setCapturedPacketLength(header->caplen);
        buffer[last].setOriginalPacketLength(header->len);
        buffer[last].setTimestamp(header->ts.tv_usec); // TODO will usec be precise enough?
        buffer[last].setPacketData(packet);
        ++last;

        D("push locking");
        std::lock_guard<std::mutex> guard(m_mutex);
        m_rcvdPacket = true;
        m_condVar.notify_one();
        D("push releasing");
    }

    void pop()
    {
        first = (first+1) % buffer.size() ;
        --size;
        if (empty())
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            m_rcvdPacket = false;
        }
    }

    void write()
    {
        log(LogLevel::INFO, "Writing to the output file started.");
        while (!stop())
        {
            D("write locking");
            std::unique_lock<std::mutex> mlock(m_mutex);
            m_condVar.wait(mlock, std::bind(&RingBuffer::receivedPacket, this));
            mlock.unlock();
            while(!empty())
            {
                D("write writing");
                buffer[first].write(oFile); // FIXME mutex needed
                pop();
            }
            D("write releasing");
        }
        log(LogLevel::INFO, "Writing to the output file stopped.");
    }
    
    void notifyCondVar()
    {
        m_condVar.notify_one();
    }
};
