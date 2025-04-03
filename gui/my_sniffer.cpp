#include "my_sniffer.h"
#include <iostream>
#include <pcap.h>

MySnifferWidget::MySnifferWidget()
{
    pack_start(m_main_box, Gtk::PACK_EXPAND_WIDGET);

    // Menu bar
    auto file_menu = Gtk::manage(new Gtk::Menu());
    auto file_item = Gtk::manage(new Gtk::MenuItem("File"));
    file_item->set_submenu(*file_menu);
    m_menu_bar.append(*file_item);

    auto new_item = Gtk::manage(new Gtk::MenuItem("New"));
    new_item->signal_activate().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_menu_file_new));
    file_menu->append(*new_item);

    auto open_item = Gtk::manage(new Gtk::MenuItem("Open"));
    open_item->signal_activate().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_menu_file_open));
    file_menu->append(*open_item);

    auto exit_item = Gtk::manage(new Gtk::MenuItem("Exit"));
    exit_item->signal_activate().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_menu_file_exit));
    file_menu->append(*exit_item);

    m_main_box.pack_start(m_menu_bar, Gtk::PACK_SHRINK);

    // Toolbar
    m_toolbar.append(m_start_button);
    m_toolbar.append(m_stop_button);
    m_start_button.set_label("Start");
    m_stop_button.set_label("Stop");
    m_start_button.signal_clicked().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_start_button_clicked));
    m_stop_button.signal_clicked().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_stop_button_clicked));
    m_main_box.pack_start(m_toolbar, Gtk::PACK_SHRINK);

    // Filter box
    m_source_label.set_label("Source IP:");
    m_dest_label.set_label("Destination IP:");
    m_port_label.set_label("Port:");

    m_filter_box.pack_start(m_source_label, Gtk::PACK_SHRINK);
    m_filter_box.pack_start(m_source_entry, Gtk::PACK_EXPAND_WIDGET);
    m_filter_box.pack_start(m_dest_label, Gtk::PACK_SHRINK);
    m_filter_box.pack_start(m_dest_entry, Gtk::PACK_EXPAND_WIDGET);
    m_filter_box.pack_start(m_port_label, Gtk::PACK_SHRINK);
    m_filter_box.pack_start(m_port_entry, Gtk::PACK_EXPAND_WIDGET);

    // Connect signals
    m_source_entry.signal_changed().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_filter_changed));
    m_dest_entry.signal_changed().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_filter_changed));
    m_port_entry.signal_changed().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_filter_changed));

    m_main_box.pack_start(m_filter_box, Gtk::PACK_SHRINK);

    // Interface dropdown
    if(pcap_findalldevs(&alldevs, error_buffer) == -1) {
        m_interface_dropdown.append(std::string("No devices found: ") + error_buffer);
    } else {
        for(pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if(d->name) {
                m_interface_dropdown.append(d->name);
            }
        }
        pcap_freealldevs(alldevs);
    }
    m_interface_dropdown.set_active(0);
    m_interface_dropdown.signal_changed().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_interface_selected));
    m_main_box.pack_start(m_interface_dropdown, Gtk::PACK_SHRINK);

    // Promisc mode
    m_promiscuous_mode_check.set_label("Enable Promiscuous Mode");
    m_promiscuous_mode_check.set_active(false);
    m_promiscuous_mode_check.signal_toggled().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_promiscuous_mode_toggled));
    m_main_box.pack_start(m_promiscuous_mode_check, Gtk::PACK_SHRINK);

    // TreeView
    m_list_store = Gtk::ListStore::create(m_columns);
    m_tree_view.set_model(m_list_store);

    // Create columns manually so we can color background + do row_activated
    create_treeview_column("No.",       m_columns.col_packet_num);
    create_treeview_column("Protocol",  m_columns.col_protocol);
    create_treeview_column("Source",    m_columns.col_source);
    create_treeview_column("Destination", m_columns.col_destination);
    create_treeview_column("Info",      m_columns.col_info);

    // scrolled window
    m_scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
    m_scrolled_window.add(m_tree_view);
    m_main_box.pack_start(m_scrolled_window, Gtk::PACK_EXPAND_WIDGET);

    // Connect row_activated to open detail window
    m_tree_view.signal_row_activated().connect(
        sigc::mem_fun(*this, &MySnifferWidget::on_row_activated));
}

MySnifferWidget::~MySnifferWidget()
{
    stop_sniffing_thread();
}

// Create columns with cell data function to color background
void MySnifferWidget::create_treeview_column(const Glib::ustring& title,
                                             const Gtk::TreeModelColumnBase& model_col)
{
    auto col = Gtk::manage(new Gtk::TreeViewColumn(title));
    auto renderer = Gtk::manage(new Gtk::CellRendererText());
    col->pack_start(*renderer, true);
    col->add_attribute(renderer->property_text(), model_col);

    col->set_cell_data_func(
        *renderer,
        [this](Gtk::CellRenderer* r, const Gtk::TreeModel::iterator& iter){
            if(!iter) return;
            Gtk::TreeModel::Row row = *iter;
            Glib::ustring color = row[m_columns.col_color];

            auto text_renderer = dynamic_cast<Gtk::CellRendererText*>(r);
            if(text_renderer)
            {
                text_renderer->property_background() = color;
                text_renderer->property_foreground() = "black"; // always black text
            }
        }
    );

    m_tree_view.append_column(*col);
}

// Menu signals
void MySnifferWidget::on_menu_file_new()
{
    std::cout << "[MySnifferWidget] New selected\n";
}
void MySnifferWidget::on_menu_file_open()
{
    std::cout << "[MySnifferWidget] Open selected\n";
}
void MySnifferWidget::on_menu_file_exit()
{
    std::cout << "[MySnifferWidget] Exit clicked (we're a widget)\n";
}

// Start/Stop
void MySnifferWidget::on_start_button_clicked()
{
    if(!handle) {
        std::cerr << "Handle not initialized. Select interface first.\n";
        return;
    }
    if(sniffing_active) {
        std::cout << "Already sniffing.\n";
        return;
    }
    start_sniffing_thread();
}

void MySnifferWidget::on_stop_button_clicked()
{
    stop_sniffing_thread();
}

void MySnifferWidget::start_sniffing_thread()
{
    sniffing_active = true;
    sniffing_thread = std::thread([this]() {
        std::cout << "Starting pcap_loop...\n";
        pcap_loop(this->handle, 0, &Sniffing::packet_callback, (u_char*)this);
        std::cout << "pcap_loop ended.\n";
    });
}

void MySnifferWidget::stop_sniffing_thread()
{
    if(!sniffing_active) {
        std::cout << "Not sniffing.\n";
        return;
    }
    pcap_breakloop(handle);

    if(sniffing_thread.joinable()) {
        sniffing_thread.join();
    }

    if(handle) {
        pcap_close(handle);
        handle = nullptr;
    }
    sniffing_active = false;
    std::cout << "Sniffing stopped.\n";
}

// Filter
void MySnifferWidget::on_filter_changed()
{
    port_filter = m_port_entry.get_text();
    std::cout << "[Filter changed] -> " << port_filter << "\n";

    filter.netmask_lookup(interface, error_buffer);
    if(!handle) {
        std::cerr << "Invalid handle. Can't set filter.\n";
        return;
    }
    filter.filter_processing(handle, port_filter.c_str(), 0, filter.get_net());
}

// Interface
void MySnifferWidget::on_interface_selected()
{
    interface = m_interface_dropdown.get_active_text();
    handle = device.init_packet_capture(interface.c_str(), promiscuous_mode_enabled);
    if(handle) {
        std::cout << "[Interface] Capturing on " << interface << "\n";
    } else {
        std::cerr << "[Interface] Failed to start on " << interface << "\n";
        std::cerr << "Error: " << device.error_buffer << "\n";
    }
}

void MySnifferWidget::on_promiscuous_mode_toggled()
{
    promiscuous_mode_enabled = m_promiscuous_mode_check.get_active();
    std::cout << "Promisc -> " << (promiscuous_mode_enabled ? "ENABLED" : "DISABLED") << "\n";
}

// Called by sniffing callback
void MySnifferWidget::queue_packet(int packet_num,
                                   const Glib::ustring& protocol,
                                   const Glib::ustring& src,
                                   const Glib::ustring& dst,
                                   const Glib::ustring& info,
                                   const uint8_t* data_ptr,
                                   size_t data_len)
{
    // Must do GUI updates on main thread
    Glib::signal_idle().connect_once(
        [this, packet_num, protocol, src, dst, info, data_ptr, data_len]() {
            add_packet_to_list(packet_num, protocol, src, dst, info, data_ptr, data_len);
        }
    );
}

void MySnifferWidget::add_packet_to_list(int packet_num,
                                         const Glib::ustring& protocol,
                                         const Glib::ustring& src,
                                         const Glib::ustring& dst,
                                         const Glib::ustring& info,
                                         const uint8_t* data_ptr,
                                         size_t data_len)
{
    // Decide background color
    Glib::ustring color = "white";
    if(protocol == "ARP")     color = "Khaki";
    else if(protocol == "ICMP") color = "LightGreen";
    else if(protocol == "UDP")  color = "LightSkyBlue";
    else if(protocol == "TCP")  color = "LightCoral";
    else if(protocol == "IPv6") color = "LightGray";

    auto row = *(m_list_store->append());
    row[m_columns.col_packet_num] = packet_num;
    row[m_columns.col_protocol]   = protocol;
    row[m_columns.col_source]     = src;
    row[m_columns.col_destination]= dst;
    row[m_columns.col_info]       = info;
    row[m_columns.col_color]      = color;

    // Store raw packet data
    std::vector<uint8_t> raw(data_ptr, data_ptr + data_len);
    row[m_columns.col_raw_data] = raw;
}

// Double-click (row_activated) => open detail window
void MySnifferWidget::on_row_activated(const Gtk::TreeModel::Path& path,
                                       Gtk::TreeViewColumn* column)
{
    auto iter = m_list_store->get_iter(path);
    if(!iter) return;

    Gtk::TreeModel::Row row = *iter;
    auto proto = row[m_columns.col_protocol];
    auto src   = row[m_columns.col_source];
    auto dst   = row[m_columns.col_destination];
    auto info  = row[m_columns.col_info];

    // Retrieve the raw bytes
    auto raw = row[m_columns.col_raw_data];

    // Open the detail window
    auto detail = new DetailWindow(raw, proto, src, dst, info);
    detail->show();
}
