#include "MonitoringPage.h"
#include "LineChartWidget.h"
#include <QVBoxLayout>
#include <QTableWidget>
#include <QHeaderView>

MonitoringPage::MonitoringPage(QWidget *parent)
  : QWidget(parent)
{
    setupUI();
}

void MonitoringPage::setupUI()
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(20,20,20,20);
    v->setSpacing(20);

    auto *chart = new LineChartWidget;
    chart->setData({2,5,3,6,4,7,5});
    v->addWidget(chart,1);

    auto *t = new QTableWidget(4,4);
    t->setHorizontalHeaderLabels(
        { "Time","Source","Destination","Action" });
    t->horizontalHeader()->setStretchLastSection(true);
    v->addWidget(t,1);
}
