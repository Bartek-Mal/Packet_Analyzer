#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QComboBox>
#include <QCheckBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QPlainTextEdit>
#include <QSplitter>
#include "packetthread.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStart();
    void onStop();
    void onApplyFilter();
    void onNewPacket(const PacketData &data);
    void onPacketSelected();

private:
    QComboBox   *ifaceCombo;
    QCheckBox   *promiscCheck;
    QLineEdit   *filterEdit;
    QPushButton *startBtn;
    QPushButton *stopBtn;
    QPushButton *applyBtn;

    QTableWidget   *table;
    QPlainTextEdit *detailView;
    QPlainTextEdit *hexView;
    QList<QByteArray> rawPackets;

    PacketThread *worker{nullptr};
};

#endif // MAINWINDOW_H
