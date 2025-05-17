#include <QApplication>
#include "FirewallWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    FirewallWindow w;
    w.show();
    return app.exec();
}
