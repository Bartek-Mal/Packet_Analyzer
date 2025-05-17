#include "AddRuleDialog.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QDialogButtonBox>

AddRuleDialog::AddRuleDialog(QWidget *parent)
  : QDialog(parent)
{
    setWindowTitle(tr("Add Firewall Rule"));
    auto *mainLay = new QVBoxLayout(this);

    // Form fields
    auto *form = new QFormLayout;
    enabledChk_   = new QCheckBox(tr("Enabled"));
    actionCombo_  = new QComboBox;
    actionCombo_->addItems({ tr("Allow"), tr("Block") });
    protocolCombo_= new QComboBox;
    protocolCombo_->addItems({ tr("TCP"), tr("UDP"), tr("ICMP"), tr("Any") });
    srcIpEdit_    = new QLineEdit;
    srcPortEdit_  = new QLineEdit;
    dstIpEdit_    = new QLineEdit;
    dstPortEdit_  = new QLineEdit;
    
    form->addRow(QString(), enabledChk_);
    form->addRow(tr("Action:"),     actionCombo_);
    form->addRow(tr("Protocol:"),   protocolCombo_);
    form->addRow(tr("Source IP:"),  srcIpEdit_);
    form->addRow(tr("Source Port:"),srcPortEdit_);
    form->addRow(tr("Dest IP:"),    dstIpEdit_);
    form->addRow(tr("Dest Port:"),  dstPortEdit_);

    mainLay->addLayout(form);

    // OK / Cancel
    auto *buttons = new QDialogButtonBox(
         QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
         Qt::Horizontal, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLay->addWidget(buttons);
}

FirewallRule AddRuleDialog::rule() const {
    FirewallRule r;
    r.enabled  = enabledChk_->isChecked();
    r.action   = actionCombo_->currentText();
    r.protocol = protocolCombo_->currentText();
    r.srcIp    = srcIpEdit_->text();
    r.srcPort  = srcPortEdit_->text();
    r.dstIp    = dstIpEdit_->text();
    r.dstPort  = dstPortEdit_->text();
    return r;
}
