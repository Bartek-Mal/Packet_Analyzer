#ifndef RULESPAGE_H
#define RULESPAGE_H

#include <QWidget>

class QTableWidget;

class RulesPage : public QWidget {
    Q_OBJECT
public:
    explicit RulesPage(QWidget *parent = nullptr);

private slots:
    void onAddRule();

private:
    void setupUI();
    QTableWidget *table_{nullptr};
};

#endif // RULESPAGE_H
