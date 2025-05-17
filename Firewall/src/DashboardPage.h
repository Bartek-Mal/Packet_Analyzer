#ifndef DASHBOARDPAGE_H
#define DASHBOARDPAGE_H

#include <QWidget>
class LineChartWidget;

class DashboardPage : public QWidget {
    Q_OBJECT
public:
    explicit DashboardPage(QWidget *parent = nullptr);
    void updateNetworkActivity(const QVector<double>& data);

private:
    LineChartWidget *chart_{nullptr};
};

#endif // DASHBOARDPAGE_H
