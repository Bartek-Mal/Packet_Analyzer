#include "optionsdialog.h"
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>

static const QList<QPair<QString, QString>> nmapOptions = {
    { "-sV", "Probe open ports to determine service/version info" },
    { "-sn", "Ping scan - disable port scan" },
    { "-Pn", "Treat all hosts as online -- skip host discovery" },
    { "-p",  "Only scan specified ports" },
    { "-O",  "Enable OS detection" },
    { "-T4", "Aggressive timing template (higher is faster)" },
    { "-A",  "Enable OS detection, version detection, script scanning, and traceroute" },
    { "-sC", "Equivalent to --script=default (run default NSE scripts)" },
};

OptionsDialog::OptionsDialog(QWidget *parent)
    : QDialog(parent), tree(new QTreeWidget), okBtn(new QPushButton(tr("OK"))),
      cancelBtn(new QPushButton(tr("Cancel")))
{
    setWindowTitle(tr("Nmap Options"));
    resize(500, 400);

    tree->setColumnCount(2);
    tree->setHeaderLabels({ tr("Option"), tr("Description") });
    tree->setRootIsDecorated(false);

    for (auto &opt : nmapOptions) {
        auto *item = new QTreeWidgetItem(tree);
        item->setText(0, opt.first);
        item->setText(1, opt.second);
        item->setCheckState(0, Qt::Unchecked);
    }

    auto *btnLay = new QHBoxLayout;
    btnLay->addStretch();
    btnLay->addWidget(okBtn);
    btnLay->addWidget(cancelBtn);

    auto *mainLay = new QVBoxLayout(this);
    mainLay->addWidget(tree, 1);
    mainLay->addLayout(btnLay);

    connect(okBtn,     &QPushButton::clicked, this, &QDialog::accept);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
}

QStringList OptionsDialog::selectedOptions() const {
    QStringList result;
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        auto *item = tree->topLevelItem(i);
        if (item->checkState(0) == Qt::Checked) {
            result << item->text(0);
        }
    }
    return result;
}
