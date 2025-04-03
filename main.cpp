#include <gtkmm.h>
#include "gui/main_menu.h"  
int main(int argc, char *argv[]) {
    auto app = Gtk::Application::create(argc, argv, "com.packet.sniffer");

    MainMenuWindow main_menu;
    return app->run(main_menu);
}
