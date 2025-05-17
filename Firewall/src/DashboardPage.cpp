#include "DashboardPage.h"
#include "LineChartWidget.h"
#include <QGridLayout>
#include <QFrame>
#include <QLabel>

DashboardPage::DashboardPage(QWidget *parent)
  : QWidget(parent)
{
    auto *grid = new QGridLayout(this);
    grid->setContentsMargins(20,20,20,20);
    grid->setHorizontalSpacing(30);
    grid->setVerticalSpacing(30);

    QStringList titles = {
        "Active Rules","Blocked Threats",
        "Allowed Traffic","Blocked Traffic"
    };
    QStringList values = { "5","12","354","27" };

    for (int i = 0; i < 4; ++i) {
        auto *f = new QFrame;
        f->setStyleSheet("background:#2a2a35; border-radius:8px;");
        auto *v = new QVBoxLayout(f);
        auto *t = new QLabel(titles[i]);
        t->setStyleSheet("color:#ffffff; font-weight:bold;");
        t->setAlignment(Qt::AlignCenter);
        auto *val = new QLabel(values[i]);
        val->setStyleSheet("color:#ffffff; font-size:24px;");
        val->setAlignment(Qt::AlignCenter);
        v->addWidget(t);
        v->addWidget(val);
        grid->addWidget(f, 0, i);
    }

    chart_ = new LineChartWidget;
    grid->addWidget(chart_, 1, 0, 1, 4);
}

void DashboardPage::updateNetworkActivity(const QVector<double>& data) {
    if (chart_) chart_->setData(data);
}
