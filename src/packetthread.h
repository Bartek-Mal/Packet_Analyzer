#ifndef PACKETTHREAD_H
#define PACKETTHREAD_H

#include <QThread>
#include <QString>
#include <QByteArray>
#include <pcap.h>

// Model danych jednego pakietu
struct PacketData {
    int     number;
    QString time;
    QString src;
    QString dst;
    QString proto;
    quint32 length;   // szerokość na przewodzie
    QString info;
    QByteArray raw;   // dane uchwycone
};
Q_DECLARE_METATYPE(PacketData)

class PacketThread : public QThread {
    Q_OBJECT

public:
    PacketThread(const QString &iface, bool promisc, const QString &filterExp, QObject *parent = nullptr);
    ~PacketThread() override;

    void run() override;
    void stop();
    void setFilter(const QString &filterExp);

signals:
    void packetCaptured(const PacketData &data);
    void errorOccurred(const QString &err);

private:
    static void pcapCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

    QString interfaceName;
    bool    promiscuous;
    QString filterExpression;
    volatile bool running;
    pcap_t  *handle;
};

#endif // PACKETTHREAD_H
