#include "SettingsPage.h"

#include <QVBoxLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QListWidget>
#include <QFileDialog>
#include <QDir>
#include <QLineEdit>    
#include <QDebug>

SettingsPage::SettingsPage(QWidget *parent)
  : QWidget(parent)
{
    setupUI();
}

void SettingsPage::setupUI()
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(20,20,20,20);
    v->setSpacing(15);

    // 1) Profiles
    {
        auto *box = new QGroupBox(tr("Profile Management"));
        auto *h = new QHBoxLayout(box);
        h->addWidget(new QLabel(tr("Active Profile:")));
        auto *combo = new QComboBox;
        combo->addItems({ tr("Domain"), tr("Private"), tr("Public") });
        connect(combo, &QComboBox::currentTextChanged,
                this, [](const QString &p){ qDebug()<<"Profile:"<<p; });
        h->addWidget(combo);
        v->addWidget(box);
    }

    // 2) Logging
    {
        auto *box = new QGroupBox(tr("Logging Configuration"));
        auto *g = new QGridLayout(box);
        auto *chk = new QCheckBox(tr("Enable Logging"));
        g->addWidget(chk,0,0,1,2);
        auto *edit = new QLineEdit;        // now recognized
        auto *btn  = new QPushButton(tr("Browse"));
        connect(btn, &QPushButton::clicked, this, [=](){
            QString f=QFileDialog::getSaveFileName(
                this, tr("Log File"), QDir::homePath(), "*.log");
            if(!f.isEmpty()) edit->setText(f);
        });
        g->addWidget(new QLabel(tr("Log File:")),1,0);
        g->addWidget(edit,                         1,1);
        g->addWidget(btn,                          1,2);
        v->addWidget(box);
    }

    // 3) Notifications
    {
        auto *box = new QGroupBox(tr("Notifications"));
        auto *h = new QVBoxLayout(box);
        auto *c1 = new QCheckBox(tr("On Rule Trigger"));
        auto *c2 = new QCheckBox(tr("On Blocked Packet"));
        connect(c1,&QCheckBox::toggled,this,[](bool on){qDebug()<<"Notify trigger:"<<on;});
        connect(c2,&QCheckBox::toggled,this,[](bool on){qDebug()<<"Notify block:"<<on;});
        h->addWidget(c1);
        h->addWidget(c2);
        v->addWidget(box);
    }

    // 4) Import/Export
    {
        auto *box = new QGroupBox(tr("Import / Export"));
        auto *h = new QHBoxLayout(box);
        auto *imp = new QPushButton(tr("Import"));
        auto *exp = new QPushButton(tr("Export"));
        connect(imp,&QPushButton::clicked,this,[]{qDebug()<<"Import clicked";});
        connect(exp,&QPushButton::clicked,this,[]{qDebug()<<"Export clicked";});
        h->addWidget(imp);
        h->addWidget(exp);
        h->addStretch();
        v->addWidget(box);
    }

    // 5) Scheduled Rules (placeholder)
    {
        auto *box = new QGroupBox(tr("Scheduled Rules"));
        auto *l = new QVBoxLayout(box);
        auto *lbl = new QLabel(tr("Schedule editor placeholder"));
        lbl->setStyleSheet("font-style:italic;color:#888;");
        l->addWidget(lbl);
        v->addWidget(box);
    }

    // 6) Geo-Blocking
    {
        auto *box = new QGroupBox(tr("Geo-Blocking"));
        auto *h = new QHBoxLayout(box);
        auto *list = new QListWidget;
        auto *add  = new QPushButton(tr("Add Country"));
        connect(add,&QPushButton::clicked,this,[]{qDebug()<<"Add Country";});
        h->addWidget(list,3);
        h->addWidget(add,1);
        v->addWidget(box);
    }

    // 7) VPN Integration
    {
        auto *box = new QGroupBox(tr("VPN Integration"));
        auto *h = new QHBoxLayout(box);
        auto *chk = new QCheckBox(tr("Require VPN"));
        auto *combo = new QComboBox;
        combo->addItems({ tr("None"), tr("eth0"), tr("tun0") });
        connect(chk,&QCheckBox::toggled,this,[](bool on){qDebug()<<"VPN:"<<on;});
        connect(combo,&QComboBox::currentTextChanged,this,[](const QString &i){qDebug()<<"VPN iface:"<<i;});
        h->addWidget(chk);
        h->addWidget(new QLabel(tr("Interface:")));
        h->addWidget(combo);
        v->addWidget(box);
    }

    v->addStretch();
}
