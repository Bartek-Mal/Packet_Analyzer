#include <QApplication>
#include "networkmapperwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    NetworkMapperWindow w;
    w.show();
    return app.exec();
}
