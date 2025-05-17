#include "networkmapperwindow.h"
#include "optionsdialog.h"

#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QGraphicsView>
#include <QTextEdit>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QStackedWidget>
#include <QFileDialog>
#include <QDir>
#include <QProcess>
#include <QCompleter>    // Required for auto-completion

NetworkMapperWindow::NetworkMapperWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // Central container and layout
    QWidget *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // --- Top switch buttons ---
    auto *switchLayout = new QHBoxLayout;
    switchLayout->setContentsMargins(20, 20, 20, 10);
    auto *btnMap = new QPushButton(tr("Map"));
    auto *btnDir = new QPushButton(tr("Dir"));
    switchLayout->addWidget(btnMap);
    switchLayout->addWidget(btnDir);
    switchLayout->addStretch();
    mainLayout->addLayout(switchLayout);

    // --- Stacked widget holding both pages ---
    stacked = new QStackedWidget;
    stacked->addWidget(createMapPage());
    stacked->addWidget(createDirPage());
    mainLayout->addWidget(stacked, /*stretch=*/1);

    // Connect switch buttons
    connect(btnMap, &QPushButton::clicked, this, [=]() {
        stacked->setCurrentIndex(0);
    });
    connect(btnDir, &QPushButton::clicked, this, [=]() {
        stacked->setCurrentIndex(1);
    });

    // Finalize window
    setCentralWidget(central);
    setWindowTitle(tr("Network Mapper"));
    resize(900, 600);
}

//-----------------------------------------------------------------------------
// Build the “Map” page
//-----------------------------------------------------------------------------
QWidget* NetworkMapperWindow::createMapPage()
{
    QWidget *page = new QWidget;
    auto *layout = new QHBoxLayout(page);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(30);

    // --- Left panel: target, options, scan button, hosts list ---
    QWidget *left = new QWidget;
    auto *leftLayout = new QVBoxLayout(left);
    leftLayout->setSpacing(10);

    // Target network input
    leftLayout->addWidget(new QLabel(tr("Target network (CIDR):")));
    targetEdit = new QLineEdit(tr("192.168.1.0/24"));
    leftLayout->addWidget(targetEdit);

    // Options input with completer
    leftLayout->addWidget(new QLabel(tr("NetMapper options:")));
    optionsEdit = new QLineEdit;
    QStringList opts = { "-sV", "-sn", "-Pn", "-p", "-O", "-T4", "-A", "-sC", "-sS", "-sU" };
    auto *completer = new QCompleter(opts, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    optionsEdit->setCompleter(completer);
    leftLayout->addWidget(optionsEdit);

    // Options dialog button
    optionsBtn = new QPushButton(tr("…"));
    optionsBtn->setFixedWidth(30);
    connect(optionsBtn, &QPushButton::clicked,
            this, &NetworkMapperWindow::showOptionsDialog);
    leftLayout->addWidget(optionsBtn);

    // Scan button
    scanBtn = new QPushButton(tr("Scan Network"));
    scanBtn->setFixedHeight(30);
    connect(scanBtn, &QPushButton::clicked,
            this, &NetworkMapperWindow::startMapScan);
    leftLayout->addWidget(scanBtn);

    // Hosts list
    hostsList = new QListWidget;
    hostsList->setStyleSheet("background:#2a2a35; color:#ffffff;");
    leftLayout->addWidget(hostsList, /*stretch=*/1);

    layout->addWidget(left, /*stretch=*/1);

    // --- Right panel: raw output and graph placeholder ---
    QWidget *right = new QWidget;
    auto *rightLayout = new QVBoxLayout(right);
    rightLayout->setSpacing(10);

    // Raw output text area
    rawOutput = new QTextEdit;
    rawOutput->setStyleSheet("background:#1e1e28; color:#ffffff;");
    rawOutput->setReadOnly(true);
    rawOutput->setPlaceholderText(tr("Raw nmap output..."));
    rightLayout->addWidget(rawOutput, /*stretch=*/2);

    // Graph placeholder
    graphView = new QGraphicsView;
    graphView->setStyleSheet("background:#2a2a35;");
    graphView->setMinimumHeight(150);
    rightLayout->addWidget(graphView, /*stretch=*/1);

    layout->addWidget(right, /*stretch=*/2);

    return page;
}

void NetworkMapperWindow::startMapScan()
{
    // Append the composed command to raw output
    QString net  = targetEdit->text();
    QString opts = optionsEdit->text();
    rawOutput->append(QString("%1 %2").arg(opts, net));
    // TODO: launch your nmap engine here
}

void NetworkMapperWindow::showOptionsDialog()
{
    OptionsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        auto chosen = dlg.selectedOptions();
        optionsEdit->setText(chosen.join(' '));
    }
}

//-----------------------------------------------------------------------------
// Build the “Dir Attack” page
//-----------------------------------------------------------------------------
QWidget* NetworkMapperWindow::createDirPage()
{
    QWidget *page = new QWidget;
    auto *layout = new QHBoxLayout(page);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(30);

    // --- Left panel: dictionary file, target, start button ---
    QWidget *left = new QWidget;
    auto *leftLayout = new QVBoxLayout(left);
    leftLayout->setSpacing(10);

    // Dictionary file selector
    leftLayout->addWidget(new QLabel(tr("Dictionary file:")));
    dictFileEdit = new QLineEdit;
    chooseDictBtn = new QPushButton(tr("Browse…"));
    auto *dictLayout = new QHBoxLayout;
    dictLayout->addWidget(dictFileEdit);
    dictLayout->addWidget(chooseDictBtn);
    leftLayout->addLayout(dictLayout);
    connect(chooseDictBtn, &QPushButton::clicked,
            this, &NetworkMapperWindow::chooseDictFile);

    // Target host/IP input
    leftLayout->addWidget(new QLabel(tr("Target host/IP:")));
    dirTargetEdit = new QLineEdit;
    dirTargetEdit->setPlaceholderText(tr("e.g. example.com or 10.0.0.5"));
    leftLayout->addWidget(dirTargetEdit);

    // Start Dir Attack button
    startDirBtn = new QPushButton(tr("Start Dir Attack"));
    startDirBtn->setFixedHeight(30);
    connect(startDirBtn, &QPushButton::clicked,
            this, &NetworkMapperWindow::startDirAttack);
    leftLayout->addWidget(startDirBtn);

    leftLayout->addStretch();  // Fills remaining space

    layout->addWidget(left, /*stretch=*/1);

    // --- Right panel: dir attack results ---
    dirOutput = new QTextEdit;
    dirOutput->setStyleSheet("background:#1e1e28; color:#ffffff;");
    dirOutput->setReadOnly(true);
    dirOutput->setPlaceholderText(tr("Directory attack results..."));
    layout->addWidget(dirOutput, /*stretch=*/2);

    return page;
}

void NetworkMapperWindow::chooseDictFile()
{
    QString file = QFileDialog::getOpenFileName(
        this,
        tr("Choose dictionary file"),
        QDir::homePath(),
        tr("Text files (*.txt);;All files (*)")
    );
    if (!file.isEmpty())
        dictFileEdit->setText(file);
}

void NetworkMapperWindow::startDirAttack()
{
    QString dict = dictFileEdit->text();
    QString tgt  = dirTargetEdit->text();
    if (dict.isEmpty() || tgt.isEmpty()) {
        dirOutput->append(tr("Please select a dictionary and a target."));
        return;
    }
    dirOutput->append(tr("Running directory attack on %1 with %2").arg(tgt, dict));
    // TODO: launch your directory-attack backend here
}
