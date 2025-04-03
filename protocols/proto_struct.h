#ifndef PROTO_STRUCT_H
#define PROTO_STRUCT_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string>
#include <netinet/in.h>

// -------------------------------------------------------------------------
// ETHERNET, VLAN, ARP – same as before
// -------------------------------------------------------------------------
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];  // Destination MAC
    u_char  ether_shost[ETHER_ADDR_LEN];  // Source MAC
    u_short ether_type;                   // Ethertype (IP, ARP, VLAN, etc.)
};

struct sniff_dot1q {
    u_short tci;         // Tag Control Info (VLAN ID, priority)
    u_short ether_type;  // Next Ethertype after VLAN
};

struct sniff_arp {
    u_short ar_hrd;
    u_short ar_pro;
    u_char  ar_hln;
    u_char  ar_pln;
    u_short ar_op;
    u_char  ar_sha[6];
    u_char  ar_sip[4];
    u_char  ar_tha[6];
    u_char  ar_tip[4];
};

// -------------------------------------------------------------------------
// IPv4, IPv6, ICMP, ICMPv6
// -------------------------------------------------------------------------
struct sniff_ip {
    u_char  ip_vhl;    
    u_char  ip_tos;    
    u_short ip_len;    
    u_short ip_id;     
    u_short ip_off;    
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char  ip_ttl;    
    u_char  ip_p;      
    u_short ip_sum;    
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

struct sniff_ipv6 {
    uint32_t ip6_flow;
    uint16_t ip6_plen;
    uint8_t  ip6_nxt;
    uint8_t  ip6_hlim;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

struct sniff_icmp {
    u_char  icmp_type;
    u_char  icmp_code;
    u_short icmp_sum;
    u_short icmp_id;
    u_short icmp_seq;
};

struct sniff_icmpv6 {
    uint8_t  icmp6_type;
    uint8_t  icmp6_code;
    uint16_t icmp6_cksum;
    union {
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;
        // other ICMPv6 message formats
    } icmp6_data;
};

// -------------------------------------------------------------------------
// TCP, UDP
// -------------------------------------------------------------------------
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char  th_offx2;
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct sniff_udp {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
};

// -------------------------------------------------------------------------
// PPP (Point-to-Point Protocol)
// -------------------------------------------------------------------------
/*
 * PPP can be used over serial lines, or with PPPoE, etc.
 * A minimal PPP frame includes 1 or 2 bytes for Protocol ID, plus HDLC-like addressing & control.
 * This is a simplified version of PPP for reference.
 */
// struct sniff_ppp {
//     u_char address;  // usually 0xFF
//     u_char control;  // usually 0x03
//     u_short protocol; // LCP, IP, IPv6, etc.
// };

// -------------------------------------------------------------------------
// PPPoE (PPP over Ethernet)
// -------------------------------------------------------------------------
// #define PPPOE_VERSION_TYPE 0x11  // version=1, type=1

// struct sniff_pppoe {
//     u_char vertype;   // bits: 4 bits for version, 4 bits for type
//     u_char code;      // PPPoE code: 0x00=Session, 0x09=PADI, etc.
//     u_short session_id;
//     u_short length;   // payload length
//     // Then PPP payload...
// };

/*
 * The PPP payload inside PPPoE often starts with 2 bytes of PPP protocol
 * followed by higher-level (LCP, IP, etc.).
 */

// -------------------------------------------------------------------------
// GRE (Generic Routing Encapsulation)
// -------------------------------------------------------------------------
/*
 * GRE can encapsulate various protocols. The base GRE header can be extended 
 * with optional fields if certain flags are set.
 */
struct sniff_gre {
    u_short flags_version;  // bits: C,R,K,S,etc. + version
    u_short protocol;       // Ethertype of encapsulated payload (e.g. 0x0800 for IPv4)
    // optional fields if flags are set: checksum, key, sequence, etc.
};

// -------------------------------------------------------------------------
// IPsec AH (Authentication Header)
// -------------------------------------------------------------------------
/*
 * The Authentication Header is typically IP protocol number 51 for IPv4 or next-header=51 for IPv6.
 */
struct sniff_ipsec_ah {
    uint8_t  next_header;   // e.g. 6 for TCP, 17 for UDP
    uint8_t  payload_len;   // AH length in 32-bit words minus 2
    uint16_t reserved;
    uint32_t spi;           // Security Parameter Index
    uint32_t seq_no;        // Sequence number
    // variable Authentication Data
};

// -------------------------------------------------------------------------
// IPsec ESP (Encapsulating Security Payload)
// -------------------------------------------------------------------------
/*
 * ESP is IP protocol number 50. The header includes SPI and sequence number, 
 * then the encrypted payload, plus optional padding, and an Integrity Check Value at the end.
 */
struct sniff_ipsec_esp {
    uint32_t spi;     // Security Parameter Index
    uint32_t seq_no;  // Sequence number
    // Encrypted payload (variable), optional padding, etc.
};

// -------------------------------------------------------------------------
// OSPF (Open Shortest Path First)
// -------------------------------------------------------------------------
/*
 * OSPF is IP protocol 89. This is a minimal OSPF header structure (common).
 */
struct sniff_ospf {
    uint8_t  version;
    uint8_t  type;      // 1=Hello, 2=DB Description, 3=LS Request, 4=LS Update, 5=LS Ack
    uint16_t length;    // length of entire OSPF packet
    struct in_addr router_id;
    struct in_addr area_id;
    uint16_t checksum;  // standard IP-style checksum
    uint16_t autype;    // authentication type
    // then authentication data (8 bytes), and message-specific data
};

// -------------------------------------------------------------------------
// BGP (Border Gateway Protocol)
// -------------------------------------------------------------------------
/*
 * BGP typically runs on TCP port 179. The header is 19 bytes, not counting 
 * the marker field repeated 16 times (0xFF).
 */
#define BGP_MARKER_LEN 16

struct sniff_bgp {
    u_char marker[BGP_MARKER_LEN]; // Always 0xFF repeated
    u_short length;  // total length of BGP message
    u_char type;     // 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE
    // Then variable payload depending on type
};

// -------------------------------------------------------------------------
// DNS
// -------------------------------------------------------------------------
struct sniff_dns {
    u_short id;
    u_short flags;
    u_short q_count;
    u_short ans_count;
    u_short auth_count;
    u_short add_count;
};

// -------------------------------------------------------------------------
// DHCP (over UDP, ports 67/68)
// -------------------------------------------------------------------------
#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128

struct sniff_dhcp {
    u_char  op;    
    u_char  htype; 
    u_char  hlen;  
    u_char  hops;  
    u_int   xid;   
    u_short secs;  
    u_short flags; 
    u_int   ciaddr;
    u_int   yiaddr;
    u_int   siaddr;
    u_int   giaddr;
    u_char  chaddr[DHCP_CHADDR_LEN * 2];
    u_char  sname[DHCP_SNAME_LEN];
    u_char  file[DHCP_FILE_LEN];
    // Then variable DHCP options
};

// -------------------------------------------------------------------------
// DNS & DHCP note:
// These are generally inside UDP or TCP. The above are minimal structures.
// -------------------------------------------------------------------------

#endif // PROTO_STRUCT_H
