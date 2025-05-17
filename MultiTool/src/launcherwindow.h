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
    void launchVulnerabilityScanner();
    void launchNetMapper(); 

private:
    QTabWidget  *tabs{nullptr};
    QWidget     *siemPage{nullptr};
    QWidget     *toolsPage{nullptr};
    QWidget     *settingsPage{nullptr};

    QToolButton *snifferBtn{nullptr};
    QToolButton *vulnBtn{nullptr};
};

#endif // LAUNCHERWINDOW_H
