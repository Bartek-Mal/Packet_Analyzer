#include "blue_team_view.h"

BlueTeamView::BlueTeamView()
    : m_ids_label("[ IDS Rules Manager - Placeholder ]"),
      m_logs_label("[ Log Analyzer - Placeholder ]"),
      m_threat_label("[ Threat Intelligence - Placeholder ]"),
      m_reputation_label("[ IP Reputation Checker - Placeholder ]"),
      m_ioc_label("[ IOC Scanner - Placeholder ]"),
      m_firewall_label("[ Auto Firewall - Placeholder ]"),
      m_dashboard_label("[ SOC Dashboard - Placeholder ]")
{
    set_title("Blue Team Dashboard");
    set_default_size(1280, 800);
    add(m_main_box);

    // Menu
    build_menu();

    // layout
    m_main_box.pack_start(m_content_box, Gtk::PACK_EXPAND_WIDGET);

    m_tools_box.set_spacing(10);
    m_tools_box.set_border_width(10);
    m_tools_box.set_size_request(200, -1);

    // input left panel and view
    m_content_box.pack_start(m_tools_box, Gtk::PACK_SHRINK);
    m_content_box.pack_start(m_notebook, Gtk::PACK_EXPAND_WIDGET);

    // 1) Sniffer
    auto sniffer_widget = Gtk::manage(new MySnifferWidget());
    m_notebook.append_page(*sniffer_widget, "Packet Sniffer");

    // 2) Placeholders
    m_notebook.append_page(m_ids_label, "IDS");
    m_notebook.append_page(m_logs_label, "Log Analyzer");
    m_notebook.append_page(m_threat_label, "Threat Intel");
    m_notebook.append_page(m_reputation_label, "Reputation");
    m_notebook.append_page(m_ioc_label, "IOC");
    m_notebook.append_page(m_firewall_label, "Firewall");
    m_notebook.append_page(m_dashboard_label, "Dashboard");

    show_all_children();
}

void BlueTeamView::build_menu()
{
    auto file_menu = Gtk::manage(new Gtk::Menu());
    auto file_item = Gtk::manage(new Gtk::MenuItem("File"));
    file_item->set_submenu(*file_menu);
    m_menu_bar.append(*file_item);

    auto exit_item = Gtk::manage(new Gtk::MenuItem("Exit"));
    exit_item->signal_activate().connect([this]() { hide(); });
    file_menu->append(*exit_item);

    m_main_box.pack_start(m_menu_bar, Gtk::PACK_SHRINK);
}
