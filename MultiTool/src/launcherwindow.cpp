#include "launcherwindow.h"
#include "SonarWidget.h"  

#include <QTabWidget>
#include <QListWidget>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QToolButton>
#include <QLabel>
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSizePolicy>
#include <QPushButton>


LauncherWindow::LauncherWindow(QWidget *parent)
    : QMainWindow(parent)
{
    tabs = new QTabWidget(this);    

    // --- SIEM tab ---
    siemPage = new QWidget;
    {
        auto *grid = new QGridLayout(siemPage);
        grid->setContentsMargins(20,20,20,20);
        grid->setHorizontalSpacing(30);
        grid->setVerticalSpacing(30);

        // rozciągnięcie kolumn i wierszy
        grid->setColumnStretch(0,1);
        grid->setColumnStretch(1,2);
        grid->setRowStretch(0,1);
        grid->setRowStretch(1,1);
        grid->setRowStretch(2,0);

        // 1) Live Alerts (0,0)
        auto *liveAlerts = new QListWidget;
        liveAlerts->setStyleSheet("background:#2a2a35; color:#ffffff; padding:10px;");
        liveAlerts->addItem("HIGH   – IDS alert – 5 mins ago");
        liveAlerts->addItem("MEDIUM – Firewall alert – 15 mins ago");
        liveAlerts->addItem("MEDIUM – IPS alert – 30 mins ago");
        liveAlerts->addItem("LOW    – Update failure – 1 hour ago");
        grid->addWidget(liveAlerts, 0, 0);

        // 2) Sonar / Network Map (0–1,1)
        auto *sonar = new SonarWidget;
        grid->addWidget(sonar, 0, 1, 2, 1);

        // 3) Traffic Graph placeholder (1,0)
        auto *traffic = new QLabel(tr("Traffic Graph"));
        traffic->setAlignment(Qt::AlignCenter);
        traffic->setStyleSheet("background:#2a2a35; color:#888888; font-size:16px; padding:20px;");
        grid->addWidget(traffic, 1, 0);

        // 4) Recent Events (2,0)
        auto *recentEvents = new QListWidget;
        recentEvents->setStyleSheet("background:#2a2a35; color:#ffffff; padding:10px;");
        recentEvents->addItem("Info    – Failed login – 3 mins ago");
        recentEvents->addItem("Notice  – New connection – 25 mins ago");
        recentEvents->addItem("Warning – Port scan detected – 1 hour ago");
        recentEvents->addItem("Info    – Rule updated – 2 hours ago");
        grid->addWidget(recentEvents, 2, 0);

        // 5) Start Scan button (2,1)
        auto *btnScan = new QPushButton(tr("Start Scan"));
        btnScan->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        btnScan->setStyleSheet(
            "background:#0a64c8; color:#ffffff; padding:10px; border-radius:6px;");
        grid->addWidget(btnScan, 2, 1);
    }
    tabs->addTab(siemPage, tr("SIEM"));

    // --- TOOLS tab ---
    toolsPage = new QWidget;
    {
        auto *outer = new QVBoxLayout(toolsPage);
        outer->addStretch();

        auto *hCenter = new QHBoxLayout;
        hCenter->addStretch();

        auto *grid = new QGridLayout;
        grid->setHorizontalSpacing(40);
        grid->setVerticalSpacing(40);

        const int columns = 3;
        const int tileSize = 180;
        const int iconSize = 100;

        // Prepare rows/cols stretch
        QString iconsDir = QCoreApplication::applicationDirPath()
                         + "/../MultiTool/src/icons";
        QDir dir(iconsDir);
        QStringList files = dir.entryList(QStringList() << "*.png", QDir::Files);
        int rows = (files.size() + columns - 1) / columns;
        for(int r=0; r<rows; ++r) grid->setRowStretch(r,1);
        for(int c=0; c<columns; ++c) grid->setColumnStretch(c,1);

        // Factory
        auto makeTile = [&](const QString &filename){
            QString absPath = dir.filePath(filename);
            QIcon icon( QFile::exists(absPath)
                        ? absPath
                        : QString(":/icons/%1").arg(filename) );
            QToolButton *btn = new QToolButton;
            btn->setFixedSize(tileSize,tileSize);
            btn->setIcon(icon);
            btn->setIconSize(QSize(iconSize,iconSize));
            btn->setToolButtonStyle(Qt::ToolButtonIconOnly);
            btn->setStyleSheet(R"(
                QToolButton { background-color:#2a2a35; border-radius:12px; }
                QToolButton:hover { background-color:#0a64c8; }
            )");
            return btn;
        };

        // Place tiles
        for(int i=0; i<files.size(); ++i) {
            int r = i/columns, c = i%columns;
            QString fn = files.at(i);
            QToolButton *tile = makeTile(fn);

            if(fn=="network.png") {
                snifferBtn = tile;
                connect(tile, &QToolButton::clicked,
                        this, &LauncherWindow::launchPacketSniffer);
            }
            else if(fn=="ioc.png") {
                vulnBtn = tile;
                connect(tile, &QToolButton::clicked,
                        this, &LauncherWindow::launchIOCScanner);
            }
            else if (fn == "netmapper.png") {
                connect(tile, &QToolButton::clicked,
                        this, &LauncherWindow::launchNetMapper);
            }
            else if (fn == "firewall.png") {
                connect(tile, &QToolButton::clicked,
                        this, &LauncherWindow::launchFirewall);
            }
            else if (fn == "vuln.png") {
                connect(tile, &QToolButton::clicked,
                        this, &LauncherWindow::launchVulnerabilityScanner);
            }


            grid->addWidget(tile, r, c);
        }

        hCenter->addLayout(grid);
        hCenter->addStretch();
        outer->addLayout(hCenter);
        outer->addStretch();
    }
    tabs->addTab(toolsPage, tr("Tools"));

    // --- SETTINGS tab ---
    settingsPage = new QWidget;
    {
        auto *v = new QVBoxLayout(settingsPage);
        auto *lbl = new QLabel("Settings coming soon");
        lbl->setStyleSheet("color:#8888ff;");
        v->addWidget(lbl);
        v->addStretch();
    }
    tabs->addTab(settingsPage, tr("Settings"));

    setCentralWidget(tabs);
    setWindowTitle(tr("Launcher"));
}

void LauncherWindow::launchPacketSniffer()
{
    QString exe = QDir(QCoreApplication::applicationDirPath())
                  .absoluteFilePath("../PacketSniffer/PacketSniffer");
    if (QFile::exists(exe))
        QProcess::startDetached(exe);
}

void LauncherWindow::launchIOCScanner()
{
    QString exe = QDir(QCoreApplication::applicationDirPath())
                  .absoluteFilePath("../IOCScanner/IOCScanner");
    if (QFile::exists(exe))
        QProcess::startDetached(exe);
}

void LauncherWindow::launchNetMapper()
{
    QString exe = QDir(QCoreApplication::applicationDirPath())
                  .absoluteFilePath("../NetMapper/NetMapper");
    if (QFile::exists(exe))
        QProcess::startDetached(exe);
}

void LauncherWindow::launchFirewall()
{
    QString exe = QDir(QCoreApplication::applicationDirPath())
                  .absoluteFilePath("../Firewall/Firewall");
    if (QFile::exists(exe))
        QProcess::startDetached(exe);
}

void LauncherWindow::launchVulnerabilityScanner()
{
    QString exe = QDir(QCoreApplication::applicationDirPath())
                  .absoluteFilePath("../VulnerabilityScanner/VulnerabilityScanner");
    if (QFile::exists(exe))
        QProcess::startDetached(exe);
}