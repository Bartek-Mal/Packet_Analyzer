#include "packetthread.h"
#include <QDateTime>
#include "devices/devices.h"
#include "filter/filter.h"
#include "protocols/proto_struct.h"

#include <arpa/inet.h>    // inet_ntop, ntohs, ntohl
#include <netinet/in.h>   // IPv4/IPv6 defs

PacketThread::PacketThread(const QString &iface, bool promisc, const QString &filterExp, QObject *parent)
    : QThread(parent)
    , interfaceName(iface)
    , promiscuous(promisc)
    , filterExpression(filterExp)
    , running(false)
    , handle(nullptr)
{
    qRegisterMetaType<PacketData>("PacketData");
}

PacketThread::~PacketThread() {
    stop();
    wait();
}

void PacketThread::run() {
    Devices dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = dev.init_packet_capture(interfaceName.toUtf8().constData(), promiscuous);
    if (!handle) {
        emit errorOccurred(QString("Nie można otworzyć urządzenia: %1").arg(interfaceName));
        return;
    }

    if (!filterExpression.isEmpty()) {
        Filters f;
        f.netmask_lookup(interfaceName.toUtf8().constData(), errbuf);
        f.filter_processing(handle, filterExpression.toUtf8().constData(), 1, f.get_mask());
    }

    running = true;
    pcap_loop(handle, 0, PacketThread::pcapCallback, reinterpret_cast<u_char*>(this));
    pcap_close(handle);
}

void PacketThread::stop() {
    running = false;
    if (handle) pcap_breakloop(handle);
}

void PacketThread::setFilter(const QString &filterExp) {
    filterExpression = filterExp;
    if (handle && !filterExpression.isEmpty()) {
        char errbuf[PCAP_ERRBUF_SIZE];
        Filters f;
        f.netmask_lookup(interfaceName.toUtf8().constData(), errbuf);
        f.filter_processing(handle, filterExpression.toUtf8().constData(), 1, f.get_mask());
    }
}

void PacketThread::pcapCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *self = reinterpret_cast<PacketThread*>(user);
    if (!self->running) return;

    static int count = 0;
    ++count;

    // Timestamp z milisekundami
    QDateTime dt = QDateTime::fromSecsSinceEpoch(h->ts.tv_sec)
                       .addMSecs(h->ts.tv_usec / 1000);
    QString timeStr = dt.toString("hh:mm:ss.zzz");

    const u_char *packet = bytes;

    // --- ETHERNET ---
    const auto *eth = reinterpret_cast<const sniff_ethernet*>(packet);
    quint16 etherType = ntohs(eth->ether_type);

    PacketData d;
    d.number = count;
    d.time   = timeStr;
    d.length = h->len;
    d.info.clear();

    if (etherType == 0x0806) {
        // ARP
        const auto *arp = reinterpret_cast<const sniff_arp*>(packet + SIZE_ETHERNET);
        d.proto = "ARP";

        char bufSrc[INET_ADDRSTRLEN], bufDst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->ar_sip, bufSrc, sizeof bufSrc);
        inet_ntop(AF_INET, arp->ar_tip, bufDst, sizeof bufDst);
        d.src = QString::fromUtf8(bufSrc);
        d.dst = QString::fromUtf8(bufDst);

        quint16 op = ntohs(arp->ar_op);
        if (op == 1) {
            d.info = QString("Who has %1? Tell %2").arg(bufDst).arg(bufSrc);
        } else if (op == 2) {
            // MAC z arp->ar_sha
            QString sha = QString("%1:%2:%3:%4:%5:%6")
                .arg(arp->ar_sha[0],2,16,QChar('0'))
                .arg(arp->ar_sha[1],2,16,QChar('0'))
                .arg(arp->ar_sha[2],2,16,QChar('0'))
                .arg(arp->ar_sha[3],2,16,QChar('0'))
                .arg(arp->ar_sha[4],2,16,QChar('0'))
                .arg(arp->ar_sha[5],2,16,QChar('0'));
            d.info = QString("%1 is at %2").arg(bufSrc).arg(sha);
        } else {
            d.info = QString("ARP op %1").arg(op);
        }

    } else if (etherType == 0x86DD) {
        // IPv6
        const auto *ip6 = reinterpret_cast<const sniff_ipv6*>(packet + SIZE_ETHERNET);
        d.proto = "IPv6";
        char buf6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, buf6, sizeof buf6);  d.src = buf6;
        inet_ntop(AF_INET6, &ip6->ip6_dst, buf6, sizeof buf6);  d.dst = buf6;
        d.info  = QString("NextHdr: %1  Payload: %2")
                      .arg(ip6->ip6_nxt)
                      .arg(ntohs(ip6->ip6_plen));

    } else if (etherType == 0x0800) {
        // IPv4
        const auto *ip = reinterpret_cast<const sniff_ip*>(packet + SIZE_ETHERNET);
        int size_ip = IP_HL(ip) * 4;
        d.src = inet_ntoa(ip->ip_src);
        d.dst = inet_ntoa(ip->ip_dst);

        if (ip->ip_p == IPPROTO_TCP) {
            const auto *tcp = reinterpret_cast<const sniff_tcp*>(packet + SIZE_ETHERNET + size_ip);
            int size_tcp = TH_OFF(tcp)*4;
            int payload_len = int(h->caplen) - SIZE_ETHERNET - size_ip - size_tcp;
            if (payload_len < 0) payload_len = 0;

            // flagi
            QStringList flagsList;
            if (tcp->th_flags & TH_FIN)  flagsList << "FIN";
            if (tcp->th_flags & TH_SYN)  flagsList << "SYN";
            if (tcp->th_flags & TH_RST)  flagsList << "RST";
            if (tcp->th_flags & TH_PUSH) flagsList << "PSH";
            if (tcp->th_flags & TH_ACK)  flagsList << "ACK";
            if (tcp->th_flags & TH_URG)  flagsList << "URG";
            QString flags = flagsList.join(",");

            quint16 sp = ntohs(tcp->th_sport), dp = ntohs(tcp->th_dport);
            // HTTP/TLS heurystyka
            if      (sp==80  || dp==80)  d.proto="HTTP";
            else if (sp==443 || dp==443) d.proto="TLSv1.2";
            else                          d.proto="TCP";

            d.info = QString("[%1] %2→%3 Seq=%4 Ack=%5 Len=%6 Win=%7")
                         .arg(flags)
                         .arg(sp).arg(dp)
                         .arg(ntohl(tcp->th_seq))
                         .arg(ntohl(tcp->th_ack))
                         .arg(payload_len)
                         .arg(ntohs(tcp->th_win));

        } else if (ip->ip_p == IPPROTO_UDP) {
            const auto *udp = reinterpret_cast<const sniff_udp*>(packet + SIZE_ETHERNET + size_ip);
            quint16 sp=ntohs(udp->uh_sport), dp=ntohs(udp->uh_dport);
            // DNS heurystyka
            if (sp==53 || dp==53) d.proto="DNS";
            else                   d.proto="UDP";
            int user_len = ntohs(udp->uh_len) - 8;
            d.info = QString("%1→%2 Len=%3").arg(sp).arg(dp).arg(user_len);

        } else if (ip->ip_p == IPPROTO_ICMP) {
            d.proto="ICMP";
            d.info.clear();
        } else if (ip->ip_p == IPPROTO_IGMP) {
            d.proto="IGMP";
            d.info.clear();
        } else {
            d.proto = QString::number(ip->ip_p);
            d.info.clear();
        }
    } else {
        // Inny EtherType
        d.proto = QString("0x%1").arg(etherType,0,16);
        d.src.clear();
        d.dst.clear();
        d.info.clear();
    }

    // surowe bajty
    d.raw = QByteArray(reinterpret_cast<const char*>(bytes), h->caplen);

    emit self->packetCaptured(d);
}
