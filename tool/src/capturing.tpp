/** 
 *  @file       capturing.tpp
 *  @brief      Network traffic capture templates file
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 23.03.2017 17:51
 *   - Edited:  29.03.2017 08:50
 */



template<typename T>
Directions getPacketDirection(T *ip_hdr)
{
    for (auto devIp : g_devIps)
    {
        if (memcmp(devIp, &ip_hdr->ip_src, sizeof(*devIp)) == 0)
            return Directions::OUTBOUND;
        else if (memcmp(devIp, &ip_hdr->ip_dst, sizeof(*devIp)) == 0)
            return Directions::INBOUND;
    }
    char srcAddress[100] = {0}, dstAddress[100] = {0};
    inet_ntop(AF_INET, &ip_hdr->ip_src, srcAddress, 99);
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dstAddress, 99);
    log(LogLevel::ERROR, "Can't determine packet direction for ", srcAddress, "->", dstAddress);
    return Directions::UNKNOWN;
}


