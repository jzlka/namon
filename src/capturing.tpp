/** 
 *  @file       capturing.tpp
 *  @brief      Network traffic capture templates file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 23.03.2017 17:51
 *   - Edited:  27.03.2017 00:15
 */

#pragma once



template<typename T, typename T2>
Directions getPacketDirection(T *ip_hdr, T2* dev_ip)
{
    //static std::vector<T2> interfacesIps;

    if (memcmp(dev_ip, &ip_hdr->ip_src, sizeof(T2)))
        return Directions::OUTBOUND;
    else if (memcmp(dev_ip, &ip_hdr->ip_dst, sizeof(T2)))
        return Directions::INBOUND;
    else
        throw "Can't determine packet direction";
}


