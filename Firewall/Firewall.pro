QT       += core gui widgets
CONFIG   += c++17

SOURCES += \
    src/main.cpp \
    src/FirewallWindow.cpp \
    src/DashboardPage.cpp \
    src/RulesPage.cpp \
    src/AppsPage.cpp \
    src/MonitoringPage.cpp \
    src/SettingsPage.cpp \
    src/LineChartWidget.cpp \
    src/AddRuleDialog.cpp

HEADERS += \
    src/FirewallWindow.h \
    src/DashboardPage.h \
    src/RulesPage.h \
    src/AppsPage.h \
    src/MonitoringPage.h \
    src/SettingsPage.h \
    src/LineChartWidget.h \
    src/AddRuleDialog.h

TARGET   = Firewall
TEMPLATE = app
