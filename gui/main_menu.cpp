#include "main_menu.h"
#include <iostream>

MainMenuWindow::MainMenuWindow()
{
    set_title("Wybierz Team");
    set_default_size(600, 400);

    add(main_box);
    main_box.set_spacing(20);
    main_box.set_margin_top(40);
    main_box.set_margin_bottom(40);
    main_box.set_margin_start(40);
    main_box.set_margin_end(40);

    // Blue Team
    blue_team_button.set_label("🔵 Blue Team");
    blue_team_button.set_size_request(200, 300);
    blue_team_button.signal_clicked().connect(sigc::mem_fun(*this, &MainMenuWindow::on_blue_team_clicked));
    main_box.pack_start(blue_team_button, Gtk::PACK_EXPAND_WIDGET);

    // Red Team
    red_team_button.set_label("🔴 Red Team");
    red_team_button.set_size_request(200, 300);
    red_team_button.signal_clicked().connect(sigc::mem_fun(*this, &MainMenuWindow::on_red_team_clicked));
    main_box.pack_start(red_team_button, Gtk::PACK_EXPAND_WIDGET);

    show_all_children();
}

void MainMenuWindow::on_blue_team_clicked()
{
    if (blue_team_window && blue_team_window->is_visible()) {
        Gtk::MessageDialog dialog(*this, "Blue Team Window is already open");
        dialog.run();
        return;
    }

    // Enables BlueTeamView
    blue_team_window = new BlueTeamView();
    // Clear the pointer after window closure
    blue_team_window->signal_hide().connect(
        sigc::mem_fun(*this, &MainMenuWindow::on_sniffer_closed)
    );
    blue_team_window->show();
}

void MainMenuWindow::on_sniffer_closed()
{
    delete blue_team_window;
    blue_team_window = nullptr;
}

void MainMenuWindow::on_red_team_clicked()
{
    Gtk::MessageDialog dialog(*this, "Red Team isn't ready yet");
    dialog.run();
}
