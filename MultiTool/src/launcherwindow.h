#ifndef LAUNCHERWINDOW_H
#define LAUNCHERWINDOW_H

#include <QMainWindow>

class QTabWidget;
class QWidget;
class QToolButton;

class LauncherWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit LauncherWindow(QWidget *parent = nullptr);
    ~LauncherWindow() override = default;

private slots:
    void launchPacketSniffer();

private:
    QTabWidget  *tabs{nullptr};
    QWidget     *siemPage{nullptr};
    QWidget     *toolsPage{nullptr};
    QWidget     *settingsPage{nullptr};

    QToolButton *snifferBtn{nullptr};
};

#endif // LAUNCHERWINDOW_H
