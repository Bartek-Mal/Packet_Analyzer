#include "FirewallWindow.h"
#include "DashboardPage.h"
#include "RulesPage.h"
#include "AppsPage.h"
#include "MonitoringPage.h"
#include "SettingsPage.h"

#include <QListWidget>
#include <QStackedWidget>
#include <QHBoxLayout>

FirewallWindow::FirewallWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupSidebar();
    setupPages();

    auto *central = new QWidget;
    auto *h = new QHBoxLayout(central);
    h->setContentsMargins(0,0,0,0);
    h->addWidget(sidebar_);
    h->addWidget(pages_, 1);

    setCentralWidget(central);
    setWindowTitle("Firewall");
    resize(1000,600);

    sidebar_->setCurrentRow(0);
}

void FirewallWindow::setupSidebar() {
    sidebar_ = new QListWidget;
    sidebar_->addItems({ "Dashboard", "Rules", "Applications", "Monitoring", "Settings" });
    sidebar_->setFixedWidth(150);
}

void FirewallWindow::setupPages() {
    pages_ = new QStackedWidget;
    dashboardPage_ = new DashboardPage;
    rulesPage_     = new RulesPage;
    appsPage_      = new AppsPage;
    monitorPage_   = new MonitoringPage;
    settingsPage_  = new SettingsPage;

    pages_->addWidget(dashboardPage_);
    pages_->addWidget(rulesPage_);
    pages_->addWidget(appsPage_);
    pages_->addWidget(monitorPage_);
    pages_->addWidget(settingsPage_);

    connect(sidebar_, &QListWidget::currentRowChanged,
            pages_,   &QStackedWidget::setCurrentIndex);
}
