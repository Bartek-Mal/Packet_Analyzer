// sniffing.h
#ifndef SNIFFING_H
#define SNIFFING_H

#include <pcap.h>

class Sniffing
{
public:
    Sniffing();
    ~Sniffing();

    static void packet_callback(u_char* userData,
                                const struct pcap_pkthdr* header,
                                const u_char* packet);
};

#endif
