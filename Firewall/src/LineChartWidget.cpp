#include "LineChartWidget.h"
#include <QPainter>
#include <QPen>
#include <QPaintEvent>
#include <QPolygon>
#include <algorithm>

LineChartWidget::LineChartWidget(QWidget *parent)
  : QWidget(parent)
{
    setMinimumHeight(200);
    // Demo data
    setData({1,4,2,5,3,6,4,7});
}

void LineChartWidget::setData(const QVector<double>& d) {
    data_ = d;
    update();
}

void LineChartWidget::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.fillRect(rect(), QColor("#2a2a35"));
    if (data_.size()<2) return;

    int w = width(), h = height();
    double minv = *std::min_element(data_.begin(), data_.end());
    double maxv = *std::max_element(data_.begin(), data_.end());
    double span = maxv - minv; if (qFuzzyIsNull(span)) span = 1.0;

    QPolygon poly;
    for (int i=0; i<data_.size(); ++i) {
        double x = 10 + double(i)/(data_.size()-1)*(w-20);
        double y = h - (10 + (data_[i]-minv)/span*(h-20));
        poly << QPoint(int(x), int(y));
    }
    QPen pen(QColor("#0a64c8"), 2);
    p.setPen(pen);
    p.drawPolyline(poly);
}
