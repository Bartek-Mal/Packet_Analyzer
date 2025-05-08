#include "packetthread.h"
#include <QDateTime>
#include <QCoreApplication>
#include "devices.h"
#include "filter.h"
#include "protocols/proto_struct.h"
#include <arpa/inet.h>

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
    auto self = reinterpret_cast<PacketThread*>(user);
    if (!self->running) return;

    static int count = 0;
    ++count;

    // timestamp z milisekundami
    QDateTime dt = QDateTime::fromSecsSinceEpoch(h->ts.tv_sec)
                       .addMSecs(h->ts.tv_usec/1000);
    QString timeStr = dt.toString("hh:mm:ss.zzz");

    // parsowanie Ethernet + IPv4
    const u_char *packet = bytes;
    const auto *ip = reinterpret_cast<const sniff_ip*>(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip)*4;
    QString src = inet_ntoa(ip->ip_src);
    QString dst = inet_ntoa(ip->ip_dst);

    QString proto, info;
    if (ip->ip_p == IPPROTO_TCP) {
        proto = "TCP";
        auto *tcp = reinterpret_cast<const sniff_tcp*>(packet + SIZE_ETHERNET + size_ip);
        info = QString("%1 → %2")
                   .arg(ntohs(tcp->th_sport))
                   .arg(ntohs(tcp->th_dport));
    } else if (ip->ip_p == IPPROTO_UDP) {
        proto = "UDP";
        auto *udp = reinterpret_cast<const sniff_udp*>(packet + SIZE_ETHERNET + size_ip);
        info = QString("%1 → %2")
                   .arg(ntohs(udp->uh_sport))
                   .arg(ntohs(udp->uh_dport));
    } else if (ip->ip_p == IPPROTO_ICMP) {
        proto = "ICMP";
    } else {
        proto = QString::number(ip->ip_p);
    }

    // copy raw
    QByteArray raw(reinterpret_cast<const char*>(bytes), h->caplen);

    PacketData d{ count, timeStr, src, dst, proto, (int)h->len, info, raw };
    emit self->packetCaptured(d);
}
