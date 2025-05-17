#ifndef OPTIONSDIALOG_H
#define OPTIONSDIALOG_H

#include <QDialog>
#include <QStringList>

class QTreeWidget;
class QTreeWidgetItem;
class QPushButton;

class OptionsDialog : public QDialog {
    Q_OBJECT

public:
    explicit OptionsDialog(QWidget *parent = nullptr);
    QStringList selectedOptions() const;

private:
    QTreeWidget *tree;
    QPushButton *okBtn;
    QPushButton *cancelBtn;
};

#endif // OPTIONSDIALOG_H
