#include "devices/devices.h"
#include "gui/gui.h"
#include <iostream>
#include <string> 

int main() {
    auto app = Gtk::Application::create("org.gtkmm.examples.base");

    MyWindow window;

    return app->run(window);
 }
