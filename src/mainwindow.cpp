#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <pcap.h>
#include <QTextStream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // central + layout
    QWidget *central = new QWidget(this);
    auto *vLayout = new QVBoxLayout;

    // --- góra: kontrolki
    ifaceCombo   = new QComboBox;
    promiscCheck = new QCheckBox("Promiscuous");
    filterEdit   = new QLineEdit;  filterEdit->setPlaceholderText("BPF filter, np. tcp port 80");
    applyBtn     = new QPushButton("Apply Filter");
    startBtn     = new QPushButton("Start");
    stopBtn      = new QPushButton("Stop"); stopBtn->setEnabled(false);

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

    // --- środek: tabela
    table = new QTableWidget;
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels({"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"});
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // --- dół: detale + hex
    detailView = new QPlainTextEdit; detailView->setReadOnly(true);
    hexView    = new QPlainTextEdit; hexView   ->setReadOnly(true);

    auto *bottomSplitter = new QSplitter(Qt::Horizontal);
    bottomSplitter->addWidget(detailView);
    bottomSplitter->addWidget(hexView);
    bottomSplitter->setStretchFactor(0,1);
    bottomSplitter->setStretchFactor(1,1);

    auto *mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(table);
    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setStretchFactor(0,3);
    mainSplitter->setStretchFactor(1,1);

    vLayout->addWidget(mainSplitter);
    central->setLayout(vLayout);
    setCentralWidget(central);
    setWindowTitle("Packet Sniffer");

    // --- wypisz interfejsy
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alld=nullptr;
    if (pcap_findalldevs(&alld, errbuf)==0) {
        for (auto d=alld; d; d=d->next)
            ifaceCombo->addItem(d->name);
        pcap_freealldevs(alld);
    }

    // --- sygnały
    connect(startBtn, &QPushButton::clicked, this, &MainWindow::onStart);
    connect(stopBtn,  &QPushButton::clicked, this, &MainWindow::onStop);
    connect(applyBtn, &QPushButton::clicked, this, &MainWindow::onApplyFilter);
    connect(table,   &QTableWidget::itemSelectionChanged, this, &MainWindow::onPacketSelected);
}

MainWindow::~MainWindow(){
    if (worker) {
        worker->stop();
        worker->wait();
    }
}

void MainWindow::onStart(){
    table->setRowCount(0);
    rawPackets.clear();
    startBtn->setEnabled(false);
    stopBtn->setEnabled(true);
    applyBtn->setEnabled(false);

    worker = new PacketThread(ifaceCombo->currentText(),
                              promiscCheck->isChecked(),
                              filterEdit->text(), this);
    connect(worker, &PacketThread::packetCaptured, this, &MainWindow::onNewPacket);
    connect(worker, &PacketThread::errorOccurred, detailView, &QPlainTextEdit::setPlainText);
    worker->start();
}

void MainWindow::onStop(){
    if (worker) {
        worker->stop();
        worker->wait();
        delete worker;
        worker = nullptr;
    }
    startBtn->setEnabled(true);
    stopBtn->setEnabled(false);
    applyBtn->setEnabled(true);
}

void MainWindow::onApplyFilter(){
    if (worker) worker->setFilter(filterEdit->text());
}

void MainWindow::onNewPacket(const PacketData &d){
    int row = table->rowCount();
    table->insertRow(row);
    table->setItem(row,0,new QTableWidgetItem(QString::number(d.number)));
    table->setItem(row,1,new QTableWidgetItem(d.time));
    table->setItem(row,2,new QTableWidgetItem(d.src));
    table->setItem(row,3,new QTableWidgetItem(d.dst));
    table->setItem(row,4,new QTableWidgetItem(d.proto));
    table->setItem(row,5,new QTableWidgetItem(QString::number(d.length)));
    table->setItem(row,6,new QTableWidgetItem(d.info));

    rawPackets.append(d.raw);
    table->scrollToBottom();
}

void MainWindow::onPacketSelected(){
    auto sel = table->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    int idx = sel.first().row();
    const QByteArray &raw = rawPackets[idx];

    // detale (tu możesz dowolnie dopisać inne pola)
    QString details;
    QTextStream dt(&details);
    dt << "Packet: " << idx+1 << "\n"
       << "Length: " << raw.size() << " bytes\n\n";
    detailView->setPlainText(details);

    // hex + ASCII
    QString dump;
    for (int i=0; i<raw.size(); i+=16) {
        dump += QString("%1   ").arg(i,5,10,QChar('0'));
        QString h, a;
        for (int j=0; j<16; ++j) {
            if (i+j<raw.size()) {
                unsigned char c = raw.at(i+j);
                h += QString("%1 ").arg((int)c,2,16,QChar('0'));
                a += (c>=32&&c<127)?QChar(c):'.';
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
