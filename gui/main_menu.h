#ifndef MAIN_MENU_H
#define MAIN_MENU_H

#include <gtkmm.h>
#include "blue_team_view.h" 

class MainMenuWindow : public Gtk::Window {
public:
    MainMenuWindow();

private:
    Gtk::HBox main_box;
    Gtk::Button blue_team_button;
    Gtk::Button red_team_button;

    // Pointer to blue_team_window
    BlueTeamView* blue_team_window = nullptr;

    //on clicks
    void on_blue_team_clicked();
    void on_sniffer_closed();
    void on_red_team_clicked();
};

#endif // MAIN_MENU_H
