#include "AppsPage.h"
#include <QVBoxLayout>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QDebug>

AppsPage::AppsPage(QWidget *parent)
  : QWidget(parent)
{
    setupUI();
}

void AppsPage::setupUI()
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(20,20,20,20);
    v->setSpacing(10);

    auto *btn = new QPushButton("+ Add Application");
    connect(btn, &QPushButton::clicked, this, &AppsPage::onAddApplication);
    v->addWidget(btn, 0, Qt::AlignRight);

    auto *t = new QTableWidget(4,3);
    t->setHorizontalHeaderLabels({ "Name","IP Address","Port" });
    t->horizontalHeader()->setStretchLastSection(true);
    v->addWidget(t,1);
}

void AppsPage::onAddApplication()
{
    qDebug() << "[Placeholder] Add Application clicked";
}
