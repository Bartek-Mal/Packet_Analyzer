QT       += core gui widgets

CONFIG += c++17

TARGET = NetMapper
TEMPLATE = app

SOURCES += \
    src/main.cpp \
    src/networkmapperwindow.cpp \
    src/optionsdialog.cpp

HEADERS += \
    src/networkmapperwindow.h \
    src/optionsdialog.h
