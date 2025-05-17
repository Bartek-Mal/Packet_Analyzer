#ifndef ADDRULEDIALOG_H
#define ADDRULEDIALOG_H

#include <QDialog>
#include <QString>

struct FirewallRule {
    bool    enabled;
    QString action;
    QString protocol;
    QString srcIp;
    QString srcPort;
    QString dstIp;
    QString dstPort;
};

class QCheckBox;
class QComboBox;
class QLineEdit;

class AddRuleDialog : public QDialog {
    Q_OBJECT
public:
    explicit AddRuleDialog(QWidget *parent = nullptr);

    FirewallRule rule() const;

private:
    QCheckBox  *enabledChk_;
    QComboBox  *actionCombo_;
    QComboBox  *protocolCombo_;
    QLineEdit  *srcIpEdit_;
    QLineEdit  *srcPortEdit_;
    QLineEdit  *dstIpEdit_;
    QLineEdit  *dstPortEdit_;
};

#endif // ADDRULEDIALOG_H
