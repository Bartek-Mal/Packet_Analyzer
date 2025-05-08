#ifndef SNIFFING_H
#define SNIFFING_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>  
#include "protocols/proto_struct.h"

class Sniffing {
public:
    Sniffing();
    ~Sniffing();

    // callback dla pcap_loop
    static void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    // pomocnicze metody do dumpowania payloadu
    void print_payload(const u_char *payload, int len) const;
    void print_hex_ascii_line(const u_char *payload, int len, int offset) const;
};

#endif // SNIFFING_H
