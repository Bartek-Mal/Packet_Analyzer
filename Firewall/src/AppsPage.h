#ifndef APPSPAGE_H
#define APPSPAGE_H

#include <QWidget>

class AppsPage : public QWidget {
    Q_OBJECT
public:
    explicit AppsPage(QWidget *parent = nullptr);

private slots:
    void onAddApplication();

private:
    void setupUI();
};

#endif // APPSPAGE_H
