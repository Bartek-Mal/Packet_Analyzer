#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QComboBox>
#include <QCheckBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTreeWidget>
#include <QPlainTextEdit>
#include <QSplitter>
#include "packetthread.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void onStart();
    void onStop();
    void onApplyFilter();
    void onNewPacket(const PacketData &data);
    void onPacketSelected();

private:
    QComboBox      *ifaceCombo{};
    QCheckBox      *promiscCheck{};
    QLineEdit      *filterEdit{};
    QPushButton    *startBtn{};
    QPushButton    *stopBtn{};
    QPushButton    *applyBtn{};

    QTableWidget   *table{};
    QTreeWidget    *detailTree{};
    QPlainTextEdit *hexView{};
    QVector<PacketData> packets;
    PacketThread   *worker{nullptr};
};

#endif // MAINWINDOW_H
