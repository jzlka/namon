/** 
 *  @file       fileHandler.hpp
 *  @brief      Network Traffic Capturing With Application Tags
 *  @details    Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    06.03.2017 14:50
 *  Edited:     10.03.2017 16:51
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
    bool empty() const      { return size == 0; }
    bool full() const       { return size == buffer.size(); }
    void notifyCondVar()    { m_condVar.notify_all(); }
    bool receivedPacket()   { return m_rcvdPacket || stop(); }

    int push(const pcap_pkthdr *header, const u_char *packet);
    void pop();
    void write();
};
