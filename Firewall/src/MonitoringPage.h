#ifndef MONITORINGPAGE_H
#define MONITORINGPAGE_H

#include <QWidget>

class MonitoringPage : public QWidget {
    Q_OBJECT
public:
    explicit MonitoringPage(QWidget *parent = nullptr);

private:
    void setupUI();
};

#endif // MONITORINGPAGE_H
