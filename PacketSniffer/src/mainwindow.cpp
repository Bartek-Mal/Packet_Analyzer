#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <pcap.h>
#include <arpa/inet.h>
#include "protocols/proto_struct.h"

MainWindow::MainWindow(QWidget *parent)
  : QMainWindow(parent)
{
    auto *central = new QWidget(this);
    auto *vLayout = new QVBoxLayout(central);

    // ——— góra: kontrolki
    ifaceCombo   = new QComboBox;
    promiscCheck = new QCheckBox("Promiscuous");
    filterEdit   = new QLineEdit;  
    filterEdit->setPlaceholderText("BPF filter, ex. tcp port 80");
    applyBtn     = new QPushButton("Apply Filter");
    startBtn     = new QPushButton("Start");
    stopBtn      = new QPushButton("Stop");
    stopBtn->setEnabled(false);

    auto *topRow = new QHBoxLayout;
    topRow->addWidget(ifaceCombo);
    topRow->addWidget(promiscCheck);
    topRow->addWidget(filterEdit);
    topRow->addWidget(applyBtn);

    auto *btnRow = new QHBoxLayout;
    btnRow->addWidget(startBtn);
    btnRow->addWidget(stopBtn);

    vLayout->addLayout(topRow);
    vLayout->addLayout(btnRow);

    // ——— środek: tabela pakietów
    table = new QTableWidget(0,7);
    table->setHorizontalHeaderLabels(
        {"No.","Time","Source","Destination","Protocol","Length","Info"});
    // 0–5 według zawartości, 6 rozciągnięta
    for (int i = 0; i < 6; ++i)
        table->horizontalHeader()
             ->setSectionResizeMode(i, QHeaderView::ResizeToContents);
    table->horizontalHeader()
         ->setSectionResizeMode(6, QHeaderView::Stretch);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // ——— dół: drzewko + hexdump
    detailTree = new QTreeWidget;
    detailTree->setHeaderHidden(true);

    hexView    = new QPlainTextEdit;
    hexView->setReadOnly(true);

    auto *bottomSplitter = new QSplitter(Qt::Horizontal);
    bottomSplitter->addWidget(detailTree);
    bottomSplitter->addWidget(hexView);
    bottomSplitter->setStretchFactor(0,1);
    bottomSplitter->setStretchFactor(1,1);

    auto *mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(table);
    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setStretchFactor(0,3);
    mainSplitter->setStretchFactor(1,1);

    vLayout->addWidget(mainSplitter);
    setCentralWidget(central);
    setWindowTitle("Packet Sniffer");

    // ——— wypełnij interfejsy
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alld = nullptr;
    if (pcap_findalldevs(&alld, errbuf) == 0) {
        for (auto d = alld; d; d = d->next)
            ifaceCombo->addItem(d->name);
        pcap_freealldevs(alld);
    }

    // ——— połączenia sygnałów
    connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStart);
    connect(stopBtn,  &QPushButton::clicked, this, &MainWindow::onStop);
    connect(applyBtn, &QPushButton::clicked, this, &MainWindow::onApplyFilter);
    connect(table,    &QTableWidget::itemSelectionChanged,
            this,     &MainWindow::onPacketSelected);
    }

MainWindow::~MainWindow(){
    if (worker) {
        worker->stop();
        worker->wait();
    }
}

void MainWindow::onStart(){
    table->setRowCount(0);
    packets.clear();

    startBtn->setEnabled(false);
    stopBtn->setEnabled(true);
    applyBtn->setEnabled(false);

    worker = new PacketThread(ifaceCombo->currentText(),
                              promiscCheck->isChecked(),
                              filterEdit->text(), this);

    connect(worker, &PacketThread::packetCaptured, this, &MainWindow::onNewPacket);
    connect(worker, &PacketThread::errorOccurred,  [this](const QString &e){
        detailTree->clear();
        detailTree->addTopLevelItem(new QTreeWidgetItem(QStringList{"Error: " + e}));
    });

    worker->start();
}

void MainWindow::onStop(){
    if (!worker) return;
    worker->stop();
    worker->wait();
    delete worker;
    worker = nullptr;

    startBtn->setEnabled(true);
    stopBtn->setEnabled(false);
    applyBtn->setEnabled(true);
}

void MainWindow::onApplyFilter(){
    if (worker) worker->setFilter(filterEdit->text());
}

void MainWindow::onNewPacket(const PacketData &d) {
    int row = table->rowCount();
    table->insertRow(row);

    QStringList cols = {
        QString::number(d.number),
        d.time,
        d.src,
        d.dst,
        d.proto,
        QString::number(d.length),
        d.info
    };
    for (int c = 0; c < cols.size(); ++c) {
        auto *item = new QTableWidgetItem(cols[c]);
        // tło wg protokołu
        QColor bg;
        if      (d.proto.startsWith("HTTP"))  bg = QColor(255,239,213); // blado-pomarańcz
        else if (d.proto.startsWith("TLS"))   bg = QColor(224,255,255); // blado-turkus
        else if (d.proto=="TCP")              bg = QColor(230,230,255);
        else if (d.proto=="UDP")              bg = QColor(230,255,230);
        else if (d.proto=="DNS")              bg = QColor(255,228,225);
        else if (d.proto=="ARP")              bg = QColor(255,255,224);
        else if (d.proto=="IPv6")             bg = QColor(240,248,255);
        else                                  bg = QColor(245,245,245);

        item->setBackground(bg);
        // czarny tekst
        item->setForeground(QBrush(Qt::black));
        table->setItem(row, c, item);
    }

    packets.append(d);
    table->scrollToBottom();
}



void MainWindow::onPacketSelected(){
    auto sel = table->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    int idx = sel.first().row();
    const auto &d = packets.at(idx);

    // — clear i odśwież tree
    detailTree->clear();

    // Parsujemy surowy pakiet ponownie, żeby zbudować drzewko
    const u_char *packet = reinterpret_cast<const u_char*>(d.raw.constData());
    // Ethernet
    const auto *eth = reinterpret_cast<const sniff_ethernet*>(packet);
    auto *eItem = new QTreeWidgetItem(detailTree, QStringList{"Ethernet II"});
    QString srcMac = QString("%1:%2:%3:%4:%5:%6")
        .arg(eth->ether_shost[0],2,16,QChar('0'))
        .arg(eth->ether_shost[1],2,16,QChar('0'))
        .arg(eth->ether_shost[2],2,16,QChar('0'))
        .arg(eth->ether_shost[3],2,16,QChar('0'))
        .arg(eth->ether_shost[4],2,16,QChar('0'))
        .arg(eth->ether_shost[5],2,16,QChar('0'));
    QString dstMac = QString("%1:%2:%3:%4:%5:%6")
        .arg(eth->ether_dhost[0],2,16,QChar('0'))
        .arg(eth->ether_dhost[1],2,16,QChar('0'))
        .arg(eth->ether_dhost[2],2,16,QChar('0'))
        .arg(eth->ether_dhost[3],2,16,QChar('0'))
        .arg(eth->ether_dhost[4],2,16,QChar('0'))
        .arg(eth->ether_dhost[5],2,16,QChar('0'));
    new QTreeWidgetItem(eItem, QStringList{"Src: " + srcMac});
    new QTreeWidgetItem(eItem, QStringList{"Dst: " + dstMac});

    // IPv4
    const auto *ip = reinterpret_cast<const sniff_ip*>(packet + SIZE_ETHERNET);
    auto *ipItem = new QTreeWidgetItem(detailTree, QStringList{QString("Internet Protocol v%1").arg(IP_V(ip))});
    new QTreeWidgetItem(ipItem, QStringList{"Src: "  + QString(inet_ntoa(ip->ip_src))});
    new QTreeWidgetItem(ipItem, QStringList{"Dst: "  + QString(inet_ntoa(ip->ip_dst))});
    new QTreeWidgetItem(ipItem, QStringList{QString("Header Len: %1 bytes").arg(IP_HL(ip)*4)});
    new QTreeWidgetItem(ipItem, QStringList{QString("Total Len:  %1 bytes").arg(ntohs(ip->ip_len))});
    new QTreeWidgetItem(ipItem, QStringList{QString("TTL:        %1").arg(ip->ip_ttl)});
    new QTreeWidgetItem(ipItem, QStringList{QString("Proto:      %1").arg(ip->ip_p)});

    // TCP/UDP/ICMP
    int ipOffset = SIZE_ETHERNET + IP_HL(ip)*4;
    if (ip->ip_p == IPPROTO_TCP) {
        const auto *tcp = reinterpret_cast<const sniff_tcp*>(packet + ipOffset);
        auto *tItem = new QTreeWidgetItem(detailTree, QStringList{"Transmission Control Protocol"});
        new QTreeWidgetItem(tItem, QStringList{QString("Src Port: %1").arg(ntohs(tcp->th_sport))});
        new QTreeWidgetItem(tItem, QStringList{QString("Dst Port: %1").arg(ntohs(tcp->th_dport))});
        new QTreeWidgetItem(tItem, QStringList{QString("Seq:      %1").arg(qint32(ntohl(tcp->th_seq)))});
        new QTreeWidgetItem(tItem, QStringList{QString("Ack:      %1").arg(qint32(ntohl(tcp->th_ack)))});
        new QTreeWidgetItem(tItem, QStringList{QString("Flags:    0x%1").arg(tcp->th_flags,0,16)});
        new QTreeWidgetItem(tItem, QStringList{QString("Window:   %1").arg(ntohs(tcp->th_win))});
    }
    else if (ip->ip_p == IPPROTO_UDP) {
        const auto *udp = reinterpret_cast<const sniff_udp*>(packet + ipOffset);
        auto *uItem = new QTreeWidgetItem(detailTree, QStringList{"User Datagram Protocol"});
        new QTreeWidgetItem(uItem, QStringList{QString("Src Port: %1").arg(ntohs(udp->uh_sport))});
        new QTreeWidgetItem(uItem, QStringList{QString("Dst Port: %1").arg(ntohs(udp->uh_dport))});
        new QTreeWidgetItem(uItem, QStringList{QString("Length:   %1").arg(ntohs(udp->uh_len))});
    }
    else if (ip->ip_p == IPPROTO_ICMP) {
        auto *cItem = new QTreeWidgetItem(detailTree, QStringList{"Internet Control Message Protocol"});
        // dodatkowe pola ICMP możesz dodać analogicznie
    }

    detailTree->expandAll();

    // — hexdump
    QString dump;
    for (int i = 0; i < d.raw.size(); i += 16) {
        dump += QString("%1   ").arg(i,5,10,QChar('0'));
        QString h, a;
        for (int j=0; j<16; ++j) {
            if (i+j < d.raw.size()) {
                unsigned char c = d.raw[i+j];
                h += QString("%1 ").arg((int)c,2,16,QChar('0'));
                a += (c >= 32 && c < 127) ? QChar(c) : '.';
            } else {
                h += "   ";
                a += ' ';
            }
            if (j==7) h += ' ';
        }
        dump += h + "  " + a + "\n";
    }
    hexView->setPlainText(dump);
}
