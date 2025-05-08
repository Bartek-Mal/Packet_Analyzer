QT       += core gui widgets

CONFIG += c++17
CONFIG += thread

INCLUDEPATH += \
    $$PWD/devices \
    $$PWD/filter \
    $$PWD/packets \
    $$PWD/protocols

TEMPLATE = app
TARGET   = PacketSniffer

SOURCES += \
    src/main.cpp \
    src/mainwindow.cpp \
    src/packetthread.cpp \
    $$PWD/devices/devices.cpp \
    $$PWD/filter/filter.cpp \
    $$PWD/packets/sniffing.cpp

HEADERS += \
    src/mainwindow.h \
    src/packetthread.h \
    $$PWD/devices/devices.h \
    $$PWD/filter/filter.h \
    $$PWD/packets/sniffing.h \
    $$PWD/protocols/proto_struct.h

win32:LIBS += -lwpcap
unix:   LIBS += -lpcap
