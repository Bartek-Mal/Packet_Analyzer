#ifndef FIREWALLWINDOW_H
#define FIREWALLWINDOW_H

#include <QMainWindow>

class QListWidget;
class QStackedWidget;
class DashboardPage;
class RulesPage;
class AppsPage;
class MonitoringPage;
class SettingsPage;

class FirewallWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit FirewallWindow(QWidget *parent = nullptr);

private:
    void setupSidebar();
    void setupPages();

    QListWidget    *sidebar_{nullptr};
    QStackedWidget *pages_{nullptr};

    DashboardPage   *dashboardPage_{nullptr};
    RulesPage       *rulesPage_{nullptr};
    AppsPage        *appsPage_{nullptr};
    MonitoringPage  *monitorPage_{nullptr};
    SettingsPage    *settingsPage_{nullptr};
};

#endif // FIREWALLWINDOW_H
