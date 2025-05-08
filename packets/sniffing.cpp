// packets/sniffing.cpp

#include "sniffing.h"
#include <ctype.h>  // for isprint

Sniffing::Sniffing() {}
Sniffing::~Sniffing() {}

void Sniffing::print_payload(const u_char *payload, int len) const {
    int len_rem    = len;
    int line_width = 16; // bytes per line
    int line_len;
    int offset = 0;      // offset counter
    const u_char *ch = payload;

    if (len <= 0) return;

    // data fits on one line
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    // data spans multiple lines
    for (;;) {
        // compute current line length
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch, line_len, offset);
        len_rem -= line_len;
        ch      += line_len;
        offset += line_width;

        if (len_rem <= line_width) {
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

void Sniffing::print_hex_ascii_line(const u_char *payload, int len, int offset) const {
    int i;
    const u_char *ch = payload;

    // Print offset
    printf("%05d   ", offset);

    // Print hex
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch++);
        if (i == 7) printf(" ");
    }

    // Align ASCII section if less than 8 bytes
    if (len < 8) printf(" ");

    // Fill hex gap if line isn't full
    if (len < 16) {
        for (i = 0; i < 16 - len; i++) printf("   ");
    }

    printf("   ");

    // Print ASCII representation
    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%c", isprint(*ch) ? *ch : '.');
        ch++;
    }

    printf("\n");
}

void Sniffing::packet_callback(u_char * /*args*/,
                               const struct pcap_pkthdr * /*header*/,
                               const u_char *packet)
{
    // suppress unused-variable warnings
    const struct sniff_ethernet *ethernet = (const struct sniff_ethernet*)packet;
    (void)ethernet;

    static int count = 1;
    const struct sniff_ip  *ip;
    const struct sniff_tcp *tcp;
    const u_char           *payload;
    int  size_ip;
    int  size_tcp;
    int  size_payload;

    printf("\nPacket number %d:\n", count++);

    // define/compute IP header offset
    ip = (const struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // Print source and destination IP addresses
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    // Determine protocol
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }

    // This packet is TCP
    tcp = (const struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    // Define/compute TCP payload offset
    payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        Sniffing helper;
        helper.print_payload(payload, size_payload);
    }
}
