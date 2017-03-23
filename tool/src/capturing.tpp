/** 
 *  @file       capturing.tpp
 *  @brief      Network traffic capture templates file
 *  @author     Jozef Zuzelka (xzuzel00)
 *  Mail:       xzuzel00@stud.fit.vutbr.cz
 *  Created:    23.03.2017 17:51
 *  Edited:     23.03.2017 17:56
 *  Version:    1.0.0
 */

#pragma once



template<typename T, typename T2>
Directions getPacketDirection(T *ip_hdr, T2* dev_ip)
{
    if (memcmp(dev_ip, &ip_hdr->ip_src, sizeof(T2)))
        return Directions::OUTBOUND;
    else if (memcmp(dev_ip, &ip_hdr->ip_dst, sizeof(T2)))
        return Directions::INBOUND;
    else
        throw "Can't determine packet direction";
}


