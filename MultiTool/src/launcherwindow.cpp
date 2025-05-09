#include "launcherwindow.h"

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

LauncherWindow::LauncherWindow(QWidget *parent)
    : QMainWindow(parent)
{
    tabs = new QTabWidget(this);

    // --- SIEM tab (jak wcześniej) ---
    siemPage = new QWidget;
    {
        auto *h = new QHBoxLayout(siemPage);
        auto *side = new QListWidget;
        side->addItem("Option 1");
        side->addItem("Option 2");
        side->setStyleSheet("background:#1e1e28;color:#ffffff;");
        h->addWidget(side,1);
        auto *lbl = new QLabel("SIEM dashboard");
        lbl->setStyleSheet("color:#bbbbff; font-style:italic;");
        lbl->setAlignment(Qt::AlignCenter);
        h->addWidget(lbl,4);
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
            else if(fn=="vuln.png") {
                vulnBtn = tile;
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

void LauncherWindow::launchVulnerabilityScanner()
{
    QString exe = QDir(QCoreApplication::applicationDirPath())
                  .absoluteFilePath("../VulnerabilityScanner/VulnerabilityScanner");
    if (QFile::exists(exe))
        QProcess::startDetached(exe);
}
