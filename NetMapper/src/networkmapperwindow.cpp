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
#include <QWidget>
#include <QCompleter>

NetworkMapperWindow::NetworkMapperWindow(QWidget *parent)
    : QMainWindow(parent)
{
    QWidget *central = new QWidget(this);
    auto *hLayout = new QHBoxLayout(central);
    hLayout->setContentsMargins(20,20,20,20);
    hLayout->setSpacing(30);

    // ---- Left panel ----
    QWidget *left = new QWidget;
    auto *vLeft = new QVBoxLayout(left);
    vLeft->setSpacing(10);

    // Target network
    vLeft->addWidget(new QLabel(tr("Target network (CIDR):")));
    targetEdit = new QLineEdit(tr("192.168.1.0/24"));
    vLeft->addWidget(targetEdit);

    // Options line + autofill/completer
    vLeft->addWidget(new QLabel(tr("NetMapper options:")));
    optionsEdit = new QLineEdit;
    QStringList optionList = {
        "-sV", "-sn", "-Pn", "-p", "-O",
        "-T4", "-A", "-sC", "-sS", "-sU"
    };
    auto *completer = new QCompleter(optionList, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    optionsEdit->setCompleter(completer);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    optionsEdit->setCompleter(completer);
    vLeft->addWidget(optionsEdit);

    // Help button opens dialog
    optionsBtn = new QPushButton(tr("…"));
    optionsBtn->setFixedWidth(30);
    connect(optionsBtn, &QPushButton::clicked,
            this, &NetworkMapperWindow::showOptionsDialog);
    vLeft->addWidget(optionsBtn);

    // Scan network
    scanBtn = new QPushButton(tr("Scan Network"));
    scanBtn->setFixedHeight(30);
    vLeft->addWidget(scanBtn);
    connect(scanBtn, &QPushButton::clicked,
            this, &NetworkMapperWindow::startScan);

    hostsList = new QListWidget;
    hostsList->setStyleSheet("background:#2a2a35; color:#ffffff;");
    vLeft->addWidget(hostsList, 1);

    hLayout->addWidget(left, 1);

    // ---- Right panel ----
    QWidget *right = new QWidget;
    auto *vRight = new QVBoxLayout(right);
    vRight->setSpacing(10);

    // Raw output (now on top, larger)
    rawOutput = new QTextEdit;
    rawOutput->setStyleSheet("background:#1e1e28; color:#ffffff;");
    rawOutput->setReadOnly(true);
    rawOutput->setPlaceholderText(tr("Raw nmap output..."));
    vRight->addWidget(rawOutput, 2);

    // Graph view (now below)
    graphView = new QGraphicsView;
    graphView->setStyleSheet("background:#2a2a35;");
    graphView->setMinimumHeight(150);
    vRight->addWidget(graphView, 1);

    hLayout->addWidget(right, 2);

    setCentralWidget(central);
    setWindowTitle(tr("Network Mapper"));
    resize(900,600);
}

void NetworkMapperWindow::startScan()
{
    QString net = targetEdit->text();
    QString opts = optionsEdit->text();
    rawOutput->append(tr("%1 %2").arg(opts, net));
    // … launch scan engine here …
}

void NetworkMapperWindow::showOptionsDialog()
{
    OptionsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        auto opts = dlg.selectedOptions();
        optionsEdit->setText(opts.join(' '));
    }
}
