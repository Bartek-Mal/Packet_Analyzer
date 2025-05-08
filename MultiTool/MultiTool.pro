QT       += core gui widgets

CONFIG  += c++17

TEMPLATE = app
TARGET   = MultiTool

SOURCES += \
    src/main.cpp \
    src/launcherwindow.cpp

HEADERS += \
    src/launcherwindow.h

# dołączamy zasoby
RESOURCES += icons.qrc
