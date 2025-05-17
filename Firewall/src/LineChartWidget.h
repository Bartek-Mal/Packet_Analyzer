#ifndef LINECHARTWIDGET_H
#define LINECHARTWIDGET_H

#include <QWidget>
#include <QVector>

class LineChartWidget : public QWidget {
    Q_OBJECT
public:
    explicit LineChartWidget(QWidget *parent = nullptr);
    void setData(const QVector<double>&);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QVector<double> data_;
};

#endif // LINECHARTWIDGET_H
