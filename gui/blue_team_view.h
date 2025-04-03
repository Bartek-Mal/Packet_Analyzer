#ifndef BLUE_TEAM_VIEW_H
#define BLUE_TEAM_VIEW_H

#include <gtkmm.h>
#include "my_sniffer.h" // Nasz widget sniffera

class BlueTeamView : public Gtk::Window
{
public:
    BlueTeamView();
    virtual ~BlueTeamView() = default;

private:
    // Layout (GTKmm 3)
    Gtk::VBox m_main_box;    // main column
    Gtk::MenuBar m_menu_bar; // menu 
    Gtk::HBox m_content_box; // Left panel

    // Left panel placeholder
    Gtk::VBox m_tools_box;

    // Notebook
    Gtk::Notebook m_notebook;

    // Placeholders
    Gtk::Label m_ids_label;
    Gtk::Label m_logs_label;
    Gtk::Label m_threat_label;
    Gtk::Label m_reputation_label;
    Gtk::Label m_ioc_label;
    Gtk::Label m_firewall_label;
    Gtk::Label m_dashboard_label;

    // Temp metod
    void build_menu();
};

#endif // BLUE_TEAM_VIEW_H
