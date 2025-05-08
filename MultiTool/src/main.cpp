#include <QApplication>
#include <QStyleFactory>
#include "launcherwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Fusion + mocno ciemny + niebieski highlight
    app.setStyle(QStyleFactory::create("Fusion"));
    QPalette p;
    p.setColor(QPalette::Window, QColor(30,30,35));
    p.setColor(QPalette::WindowText, Qt::white);
    p.setColor(QPalette::Base, QColor(20,20,25));
    p.setColor(QPalette::AlternateBase, QColor(30,30,35));
    p.setColor(QPalette::Button, QColor(45,45,55));
    p.setColor(QPalette::ButtonText, Qt::white);
    p.setColor(QPalette::Highlight, QColor(10,100,200));
    p.setColor(QPalette::HighlightedText, Qt::white);
    app.setPalette(p);

    LauncherWindow w;
    w.showMaximized();
    return app.exec();
}
