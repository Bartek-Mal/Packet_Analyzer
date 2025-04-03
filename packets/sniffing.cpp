#include "sniffing.h"
#include <iostream>
#include <arpa/inet.h>  
#include <string>
#include "protocols/proto_struct.h"
#include "gui/my_sniffer.h" 

Sniffing::Sniffing() {}
Sniffing::~Sniffing() {}

static Glib::ustring to_hex_string(unsigned val)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%04X", val);
    return buf;
}

void Sniffing::packet_callback(u_char* userData,
                               const struct pcap_pkthdr* header,
                               const u_char* packet)
{
    auto widget = reinterpret_cast<MySnifferWidget*>(userData);

    static int count = 1;
    int packetNum = count++;

    // Basic strings for the row
    Glib::ustring proto = "UNKNOWN";
    Glib::ustring src   = "";
    Glib::ustring dst   = "";
    Glib::ustring info  = "";

    // EtherType parse
    const sniff_ethernet* eth = (const sniff_ethernet*)packet;
    uint16_t ether_type = ntohs(eth->ether_type);
    size_t offset = SIZE_ETHERNET;

    // 1) Check 802.1Q VLAN (0x8100) or multiple VLAN tags
    bool vlan_found = false;
    while (ether_type == 0x8100)
    {
        vlan_found = true;
        // parse sniff_dot1q
        const sniff_dot1q* vlan = (const sniff_dot1q*)(packet + offset);
        ether_type = ntohs(vlan->ether_type);
        offset += 4; // each VLAN tag is 4 bytes
    }

    // 2) Check PPPoE (0x8863 or 0x8864)
    if (ether_type == 0x8863) {
        proto = "PPPoE (Discovery)";
        widget->queue_packet(packetNum, proto, src, dst,
                             "[PPPoE Discovery]",
                             packet, header->len);
        return;
    }
    if (ether_type == 0x8864) {
        proto = "PPPoE (Session)";
        // Could parse sniff_pppoe. Then inside it, parse PPP (sniff_ppp).
        widget->queue_packet(packetNum, proto, src, dst,
                             "[PPPoE Session]",
                             packet, header->len);
        return;
    }

    // 3) ARP (0x0806)
    if (ether_type == 0x0806) {
        proto = "ARP";
        const sniff_arp* arp = (const sniff_arp*)(packet + offset);

        // Convert ARP IP addresses
        char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->ar_sip, sip, sizeof(sip));
        inet_ntop(AF_INET, arp->ar_tip, tip, sizeof(tip));
        src = sip;
        dst = tip;

        uint16_t op = ntohs(arp->ar_op);
        if (op == 1)      info = "ARP Request";
        else if (op == 2) info = "ARP Reply";
        else              info = "ARP ???";

        widget->queue_packet(packetNum, proto, src, dst, info,
                             packet, header->len);
        return;
    }

    // 4) IPv4 (0x0800)
    if (ether_type == 0x0800) {
        proto = "IPv4";
        const sniff_ip* ip = (const sniff_ip*)(packet + offset);

        int ip_hl = IP_HL(ip) * 4;
        src = inet_ntoa(ip->ip_src);
        dst = inet_ntoa(ip->ip_dst);

        // parse IP protocol
        switch (ip->ip_p) {
            case IPPROTO_TCP: {
                proto = "TCP";
                const sniff_tcp* tcp = (const sniff_tcp*)(packet + offset + ip_hl);
                int sport = ntohs(tcp->th_sport);
                int dport = ntohs(tcp->th_dport);
                info = "TCP ports: " + std::to_string(sport) + "->" + std::to_string(dport);

                // Check for BGP: port 179
                if (sport == 179 || dport == 179) {
                    proto = "BGP (TCP)";
                }
            } break;
            case IPPROTO_UDP: {
                proto = "UDP";
                const sniff_udp* udp = (const sniff_udp*)(packet + offset + ip_hl);
                int sport = ntohs(udp->uh_sport);
                int dport = ntohs(udp->uh_dport);
                info = "UDP ports: " + std::to_string(sport) + "->" + std::to_string(dport);

                // Check DNS or DHCP
                if (sport == 53 || dport == 53) {
                    // port 53 => DNS
                    proto = "DNS (UDP)";
                }
                else if ((sport == 67 && dport == 68) ||
                         (sport == 68 && dport == 67)) {
                    // 67/68 => DHCP
                    proto = "DHCP (UDP)";
                }
            } break;
            case IPPROTO_ICMP: {
                proto = "ICMP";
            } break;
            case IPPROTO_ICMPV6: {
                // Rare in IPv4
                proto = "ICMPv6?? (unusual in IPv4)";
            } break;
            case IPPROTO_GRE: {
                proto = "GRE";
                // Could parse sniff_gre
            } break;
            case IPPROTO_ESP: {
                proto = "IPsec ESP";
                // parse sniff_ipsec_esp if you like
            } break;
            case IPPROTO_AH: {
                proto = "IPsec AH";
                // parse sniff_ipsec_ah
            } break;
            case 89: {
                proto = "OSPF";
                // parse sniff_ospf
            } break;
            default:
                break;
        }

        widget->queue_packet(packetNum, proto, src, dst, info,
                             packet, header->len);
        return;
    }

    // 5) IPv6 (0x86DD)
    if (ether_type == 0x86DD) {
        proto = "IPv6";
        const sniff_ipv6* ip6 = (const sniff_ipv6*)(packet + offset);

        // check ip6->ip6_nxt for subprotocol
        uint8_t nxt = ip6->ip6_nxt;
        switch(nxt) {
            case IPPROTO_TCP:   proto = "TCPv6"; break;
            case IPPROTO_UDP:   proto = "UDPv6"; break;
            case IPPROTO_ICMPV6: proto = "ICMPv6"; break;
            case IPPROTO_ESP:   proto = "IPsec ESPv6"; break;
            case IPPROTO_AH:    proto = "IPsec AHv6";  break;
            case 89:            proto = "OSPFv3"; break;
            default: break;
        }

        widget->queue_packet(packetNum, proto, src, dst, "[IPv6 parse omitted]",
                             packet, header->len);
        return;
    }

    // 6) If we get here: unknown EtherType. Could be AppleTalk, IPX, etc.
    Glib::ustring hexET = to_hex_string(ether_type);
    if (vlan_found) {
        proto = "802.1Q => 0x" + hexET;
        info = "Stacked VLAN or unknown EtherType";
    } else {
        proto = "Unknown EtherType 0x" + hexET;
    }
    widget->queue_packet(packetNum, proto, src, dst, info,
                         packet, header->len);
}
