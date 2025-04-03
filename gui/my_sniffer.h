#ifndef MYSNIFFER_H
#define MYSNIFFER_H

#include <gtkmm.h>
#include <thread>
#include <vector>
#include <cstdint>
#include "devices.h"
#include "filter.h"
#include "sniffing.h"
#include "packet_columns.h"
#include "detail_window.h" 

/**
 * MySnifferWidget: A Gtk::VBox for capturing & displaying packets in a TreeView.
 * We store raw data in each row, and on row activation, open DetailWindow.
 */
class MySnifferWidget : public Gtk::VBox
{
public:
    MySnifferWidget();
    virtual ~MySnifferWidget();

    // Called by Sniffing::packet_callback to queue a new packet
    void queue_packet(int packet_num,
                      const Glib::ustring& protocol,
                      const Glib::ustring& src,
                      const Glib::ustring& dst,
                      const Glib::ustring& info,
                      const uint8_t* data_ptr,
                      size_t data_len);

private:
    // Layout
    Gtk::VBox m_main_box;
    Gtk::MenuBar m_menu_bar;
    Gtk::Toolbar m_toolbar;
    Gtk::ToolButton m_start_button, m_stop_button;

    Gtk::HBox m_filter_box;
    Gtk::Label m_source_label;
    Gtk::Entry m_source_entry;
    Gtk::Label m_dest_label;
    Gtk::Entry m_dest_entry;
    Gtk::Label m_port_label;
    Gtk::Entry m_port_entry;
    Gtk::ComboBoxText m_interface_dropdown;
    Gtk::CheckButton m_promiscuous_mode_check;

    Gtk::ScrolledWindow m_scrolled_window;
    Gtk::TreeView m_tree_view;

    PacketColumns m_columns;
    Glib::RefPtr<Gtk::ListStore> m_list_store;

    // Pcap
    Devices device;
    Filters filter;
    Sniffing sniff;
    pcap_t* handle = nullptr;
    pcap_if_t* alldevs = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE];
    bool sniffing_active = false;
    std::thread sniffing_thread;
    std::string interface;
    std::string port_filter;
    bool promiscuous_mode_enabled = false;

private:
    // Helper to create each column with a cell data func
    void create_treeview_column(const Glib::ustring& title,
                                const Gtk::TreeModelColumnBase& model_col);

    // Menubar / toolbar signals
    void on_menu_file_new();
    void on_menu_file_open();
    void on_menu_file_exit();
    void on_start_button_clicked();
    void on_stop_button_clicked();

    // Filter & interface signals
    void on_filter_changed();
    void on_interface_selected();
    void on_promiscuous_mode_toggled();

    // Start/stop capturing in a thread
    void start_sniffing_thread();
    void stop_sniffing_thread();

    // Actually insert row into the model
    void add_packet_to_list(int packet_num,
                            const Glib::ustring& protocol,
                            const Glib::ustring& src,
                            const Glib::ustring& dst,
                            const Glib::ustring& info,
                            const uint8_t* data_ptr,
                            size_t data_len);

    // Row activation – open detail window
    void on_row_activated(const Gtk::TreeModel::Path& path,
                          Gtk::TreeViewColumn* column);
};

#endif // MYSNIFFER_H
