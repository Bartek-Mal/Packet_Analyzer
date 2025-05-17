#include "RulesPage.h"
#include "AddRuleDialog.h"

#include <QVBoxLayout>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QDebug>

RulesPage::RulesPage(QWidget *parent)
  : QWidget(parent)
{
    setupUI();
}

void RulesPage::setupUI()
{
    auto *vlay = new QVBoxLayout(this);
    vlay->setContentsMargins(20,20,20,20);
    vlay->setSpacing(10);

    // Add Rule button
    auto *btn = new QPushButton(tr("+ Add Rule"));
    connect(btn, &QPushButton::clicked, this, &RulesPage::onAddRule);
    vlay->addWidget(btn, 0, Qt::AlignRight);

    // 7-column table
    table_ = new QTableWidget(0, 7, this);
    table_->setHorizontalHeaderLabels({
        tr("Enabled"),
        tr("Action"),
        tr("Protocol"),
        tr("Source IP"),
        tr("Source Port"),
        tr("Dest IP"),
        tr("Dest Port")
    });
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table_->setStyleSheet("background:#2a2a35; color:#ffffff;");
    vlay->addWidget(table_, 1);
}

void RulesPage::onAddRule()
{
    AddRuleDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted)
        return;

    auto r = dlg.rule();
    qDebug() << "Adding rule -- enabled:" << r.enabled
             << "action:" << r.action
             << "protocol:" << r.protocol
             << "src:" << r.srcIp << ":" << r.srcPort
             << "dst:" << r.dstIp << ":" << r.dstPort;

    // Insert new row
    int row = table_->rowCount();
    table_->insertRow(row);
    table_->setItem(row, 0, new QTableWidgetItem(r.enabled ? tr("Yes") : tr("No")));
    table_->setItem(row, 1, new QTableWidgetItem(r.action));
    table_->setItem(row, 2, new QTableWidgetItem(r.protocol));
    table_->setItem(row, 3, new QTableWidgetItem(r.srcIp));
    table_->setItem(row, 4, new QTableWidgetItem(r.srcPort));
    table_->setItem(row, 5, new QTableWidgetItem(r.dstIp));
    table_->setItem(row, 6, new QTableWidgetItem(r.dstPort));

    // TODO: Backend
    // backend()->addFirewallRule(r);
}
