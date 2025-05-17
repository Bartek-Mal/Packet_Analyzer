#include "iocscannerwindow.h"

#include <QToolBar>
#include <QAction>
#include <QTabWidget>
#include <QTreeView>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QListWidget>
#include <QProgressBar>
#include <QLabel>
#include <QTableView>
#include <QTextEdit>
#include <QLineEdit>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QDebug>
#include <iostream>

VulnerabilityScannerWindow::VulnerabilityScannerWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupToolbar();
    setupTabs();
    setupLogConsole();

    auto *central = new QWidget;
    auto *mainLay = new QVBoxLayout(central);
    mainLay->addWidget(tabs);
    mainLay->addWidget(logConsole);
    setCentralWidget(central);

    setWindowTitle(tr("Vulnerability Scanner"));
    resize(800, 600);
}

VulnerabilityScannerWindow::~VulnerabilityScannerWindow() = default;

void VulnerabilityScannerWindow::setupToolbar()
{
    toolbar = addToolBar(tr("Main"));
    actImport     = toolbar->addAction(tr("Import YARA"));
    actSaveReport = toolbar->addAction(tr("Save raport"));
    actSettings   = toolbar->addAction(tr("Settings"));

    actImport->setToolTip(tr("Import rules from file"));
    actSaveReport->setToolTip(tr("Save raport to file"));
    actSettings->setToolTip(tr("Application settings"));

    connect(actImport,     &QAction::triggered, this, &VulnerabilityScannerWindow::onImportRules);
    connect(actSaveReport, &QAction::triggered, this, &VulnerabilityScannerWindow::onSaveReport);
    connect(actSettings,   &QAction::triggered, this, &VulnerabilityScannerWindow::onSettings);
}

void VulnerabilityScannerWindow::setupTabs()
{
    tabs = new QTabWidget;

    setupGenerateTab();
    setupScanTab();
    setupHexdumpTab();
    setupStringsTab();

    tabs->addTab(generateTab, tr("Generate"));
    tabs->addTab(scanTab,     tr("Scan"));
    tabs->addTab(hexdumpTab,   tr("File Hexdump"));
    tabs->addTab(stringsTab,   tr("File Strings"));
}

void VulnerabilityScannerWindow::setupGenerateTab()
{
    generateTab = new QWidget;
    auto *lay = new QHBoxLayout(generateTab);

    ruleTree = new QTreeView;
    ruleTree->setHeaderHidden(true);
    lay->addWidget(ruleTree, 1);

    auto *right = new QVBoxLayout;
    ruleEditor = new QPlainTextEdit;
    ruleEditor->setPlaceholderText(tr("YARA rule…"));
    btnGenerate = new QPushButton(tr("Generate"));
    connect(btnGenerate, &QPushButton::clicked, this, &VulnerabilityScannerWindow::onGenerateClicked);

    right->addWidget(ruleEditor, 3);
    right->addWidget(btnGenerate, 0);
    lay->addLayout(right, 2);
}

void VulnerabilityScannerWindow::setupScanTab()
{
    scanTab = new QWidget;
    auto *main = new QVBoxLayout(scanTab);

    auto *fileLay = new QHBoxLayout;
    btnAddFiles  = new QPushButton(tr("Add file"));
    btnStartScan = new QPushButton(tr("Start Scan"));
    fileLay->addWidget(btnAddFiles);
    fileLay->addWidget(btnStartScan);
    connect(btnAddFiles,  &QPushButton::clicked, this, &VulnerabilityScannerWindow::onAddFiles);
    connect(btnStartScan,&QPushButton::clicked, this, &VulnerabilityScannerWindow::onStartScan);
    main->addLayout(fileLay);

    fileList = new QListWidget;
    main->addWidget(fileList, 1);

    auto *progLay = new QHBoxLayout;
    scanProgress  = new QProgressBar;
    lblScanCount  = new QLabel(tr("0/0"));
    progLay->addWidget(scanProgress, 1);
    progLay->addWidget(lblScanCount);
    main->addLayout(progLay);

    scanResults = new QTableView;
    auto *model = new QStandardItemModel(0, 5, this);
    scanResults->setModel(model);
    auto *hdr = scanResults->horizontalHeader();
    hdr->setSectionResizeMode(QHeaderView::Stretch);
    model->setHorizontalHeaderLabels({ "File","Rule","Severity","Offset","Summary" });
    main->addWidget(scanResults, 2);
}

void VulnerabilityScannerWindow::setupHexdumpTab()
{
    hexdumpTab = new QWidget;
    auto *lay = new QVBoxLayout(hexdumpTab);

    auto *top = new QHBoxLayout;
    hexFilePath = new QLineEdit;
    btnOpenHex  = new QPushButton(tr("Open File"));
    connect(btnOpenHex, &QPushButton::clicked, this, &VulnerabilityScannerWindow::onOpenHexdumpFile);
    top->addWidget(hexFilePath, 1);
    top->addWidget(btnOpenHex);
    lay->addLayout(top);

    hexView = new QTextEdit;
    hexView->setReadOnly(true);
    hexView->setPlaceholderText(tr("File hexdump…"));
    lay->addWidget(hexView, 1);
}

void VulnerabilityScannerWindow::setupStringsTab()
{
    stringsTab = new QWidget;
    auto *lay = new QVBoxLayout(stringsTab);

    auto *top = new QHBoxLayout;
    strFilePath = new QLineEdit;
    btnOpenStr  = new QPushButton(tr("Open File"));
    connect(btnOpenStr, &QPushButton::clicked, this, &VulnerabilityScannerWindow::onOpenStringsFile);
    top->addWidget(strFilePath, 1);
    top->addWidget(btnOpenStr);
    lay->addLayout(top);

    strFilter = new QLineEdit;
    strFilter->setPlaceholderText(tr("Filter (regex)..."));
    connect(strFilter, &QLineEdit::textChanged, this, &VulnerabilityScannerWindow::onFilterStrings);
    lay->addWidget(strFilter);

    strList = new QListWidget;
    lay->addWidget(strList, 1);
}

void VulnerabilityScannerWindow::setupLogConsole()
{
    logConsole = new QTextEdit;
    logConsole->setReadOnly(true);
    logConsole->setFixedHeight(100);
    logConsole->setPlaceholderText(tr("Logs and alerts..."));
}

//
// Sloty (placeholdery)
//

void VulnerabilityScannerWindow::onImportRules()    { std::cout<<"Importuj reguły YARA\n"; }
void VulnerabilityScannerWindow::onSaveReport()     { std::cout<<"Zapisz raport\n"; }
void VulnerabilityScannerWindow::onSettings()       { std::cout<<"Ustawienia\n"; }

void VulnerabilityScannerWindow::onGenerateClicked() {
    std::cout << "Generate & Validate YARA rule\n";
}

void VulnerabilityScannerWindow::onAddFiles()       { std::cout<<"Dodaj pliki\n"; }
void VulnerabilityScannerWindow::onStartScan()      { std::cout<<"Start scanning files\n"; }
void VulnerabilityScannerWindow::onOpenHexdumpFile(){ std::cout<<"Hexdump file\n"; }
void VulnerabilityScannerWindow::onOpenStringsFile(){ std::cout<<"Strings file\n"; }
void VulnerabilityScannerWindow::onFilterStrings(const QString &text){
    std::cout<<"Filter: "<<text.toStdString()<<"\n";
}
