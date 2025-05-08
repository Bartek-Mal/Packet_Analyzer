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
    // --- Setup tabs ---
    tabs = new QTabWidget(this);

    // 1) Tab SIEM
    siemPage = new QWidget;
    {
        auto *hLayout = new QHBoxLayout(siemPage);
        auto *sideList = new QListWidget;
        sideList->addItem("Option 1");
        sideList->addItem("Option 2");
        sideList->setStyleSheet("background:#1e1e28;color:#ffffff;");
        hLayout->addWidget(sideList, 1);

        auto *placeholder = new QLabel("SIEM dashboard");
        placeholder->setStyleSheet("color:#bbbbff; font-style:italic;");
        placeholder->setAlignment(Qt::AlignCenter);
        hLayout->addWidget(placeholder, 4);
    }
    tabs->addTab(siemPage, tr("SIEM"));
    
    // 2) Tab TOOLS
    toolsPage = new QWidget;
    {
        auto *outerVBox = new QVBoxLayout(toolsPage);
        outerVBox->addStretch();                   // górny odstęp

        auto *hCenter = new QHBoxLayout;
        hCenter->addStretch();                     // lewy odstęp

        auto *grid = new QGridLayout;
        grid->setHorizontalSpacing(40);
        grid->setVerticalSpacing(40);

        // Liczba kolumn, zmienia się w razie potrzeby:
        const int columns = 3;

        // Fixa wielkości kafelka i ikony:
        const int tileSize = 180;
        const int iconSize = 100;

        // Funkcja tworząca kwadratowy przycisk-ikonę
        auto makeTileIcon = [&](const QString &absPath, const QString &resName){
            QIcon icon;
            if (QFile::exists(absPath)) {
                icon = QIcon(absPath);
            } else {
                icon = QIcon(QString(":/icons/%1").arg(resName));
            }
            QToolButton *btn = new QToolButton;
            btn->setFixedSize(tileSize, tileSize);
            btn->setIcon(icon);
            btn->setIconSize(QSize(iconSize, iconSize));
            btn->setToolButtonStyle(Qt::ToolButtonIconOnly);
            btn->setStyleSheet(R"(
                QToolButton {
                    background-color: #2a2a35;
                    border-radius: 12px;
                }
                QToolButton:hover {
                    background-color: #0a64c8;
                }
            )");
            return btn;
        };

        // Ścieżka do folderu z ikonami na dysku
        QString iconsDir = QCoreApplication::applicationDirPath()
                        + "/../MultiTool/src/icons";
        QDir dir(iconsDir);

        // Pobierz wszystkie *.png
        QStringList files = dir.entryList(QStringList() << "*.png", QDir::Files);

        // Oblicz liczbę wierszy
        int rows = (files.size() + columns - 1) / columns;
        for(int r=0; r<rows; ++r)
            grid->setRowStretch(r, 1);
        for(int c=0; c<columns; ++c)
            grid->setColumnStretch(c, 1);

        // Dodaj kafelki w siatce
        for(int i=0; i<files.size(); ++i) {
            int row = i / columns;
            int col = i % columns;

            QString filename = files.at(i);                     // np. "dns.png"
            QString absPath  = dir.filePath(filename);          // "/.../src/icons/dns.png"

            QToolButton *tile = makeTileIcon(absPath, filename);

            // Jeśli to sieć, podpinamy PacketSniffer
            if(filename == "network.png") {
                snifferBtn = tile;
                connect(snifferBtn, &QToolButton::clicked,
                        this, &LauncherWindow::launchPacketSniffer);
            }

            grid->addWidget(tile, row, col);
        }

        hCenter->addLayout(grid);
        hCenter->addStretch();                    // prawy odstęp
        outerVBox->addLayout(hCenter);
        outerVBox->addStretch();                  // dolny odstęp
    }
    tabs->addTab(toolsPage, tr("Tools"));
    // 3) Tab SETTINGS
    settingsPage = new QWidget;
    {
        auto *vLayout = new QVBoxLayout(settingsPage);
        auto *lbl = new QLabel("Settings coming soon");
        lbl->setStyleSheet("color:#8888ff;");
        vLayout->addWidget(lbl);
        vLayout->addStretch();
    }
    tabs->addTab(settingsPage, tr("Settings"));

    setCentralWidget(tabs);
    setWindowTitle(tr("Launcher"));
}

void LauncherWindow::launchPacketSniffer()
{
    QString dir = QCoreApplication::applicationDirPath();
    QString exe = QDir(dir).absoluteFilePath("../PacketSniffer/PacketSniffer");
    if (!QFile::exists(exe)) {
        return;
    }
    QProcess::startDetached(exe);
}
