#include "gui.h"
#include <iostream>
#include <pcap.h>

MyWindow::MyWindow()
: m_main_box(Gtk::ORIENTATION_VERTICAL),
  m_start_button("Start"),
  m_stop_button("Stop"),
  m_source_label("Source IP:"),
  m_dest_label("Destination IP:"),
  m_port_label("Port:"),
  m_promiscuous_mode_check("Enable Promiscuous Mode") 
{
  set_title("Packet Sniffer");
  set_default_size(800, 600);

  // Menu
  auto file_menu = Gtk::make_managed<Gtk::Menu>();
  auto file_item = Gtk::make_managed<Gtk::MenuItem>("File");
  file_item->set_submenu(*file_menu);
  m_menu_bar.append(*file_item);

  // New
  auto menu_item_new = Gtk::make_managed<Gtk::MenuItem>("New");
  menu_item_new->signal_activate().connect(sigc::mem_fun(*this, &MyWindow::on_menu_file_new));
  file_menu->append(*menu_item_new);

  // Open
  auto menu_item_open = Gtk::make_managed<Gtk::MenuItem>("Open");
  menu_item_open->signal_activate().connect(sigc::mem_fun(*this, &MyWindow::on_menu_file_open));
  file_menu->append(*menu_item_open);

  // Exit
  auto menu_item_exit = Gtk::make_managed<Gtk::MenuItem>("Exit");
  menu_item_exit->signal_activate().connect(sigc::mem_fun(*this, &MyWindow::on_menu_file_exit));
  file_menu->append(*menu_item_exit);

  m_main_box.pack_start(m_menu_bar, Gtk::PACK_SHRINK);

  // Tool bar
  m_toolbar.append(m_start_button);
  m_toolbar.append(m_stop_button);
  m_start_button.signal_clicked().connect(sigc::mem_fun(*this, &MyWindow::on_start_button_clicked));
  m_stop_button.signal_clicked().connect(sigc::mem_fun(*this, &MyWindow::on_stop_button_clicked));
  m_main_box.pack_start(m_toolbar, Gtk::PACK_SHRINK);

  // Filter options
  m_filter_box.set_orientation(Gtk::ORIENTATION_HORIZONTAL);
  m_filter_box.pack_start(m_source_label, Gtk::PACK_SHRINK);
  m_filter_box.pack_start(m_source_entry, Gtk::PACK_EXPAND_WIDGET);
  m_filter_box.pack_start(m_dest_label, Gtk::PACK_SHRINK);
  m_filter_box.pack_start(m_dest_entry, Gtk::PACK_EXPAND_WIDGET);
  m_filter_box.pack_start(m_port_label, Gtk::PACK_SHRINK);
  m_filter_box.pack_start(m_port_entry, Gtk::PACK_EXPAND_WIDGET);
  m_source_entry.signal_changed().connect(sigc::mem_fun(*this, &MyWindow::on_filter_changed));
  m_dest_entry.signal_changed().connect(sigc::mem_fun(*this, &MyWindow::on_filter_changed));
  m_port_entry.signal_changed().connect(sigc::mem_fun(*this, &MyWindow::on_filter_changed));
  m_main_box.pack_start(m_filter_box, Gtk::PACK_SHRINK);

  // a list of devs
  if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
      m_interface_dropdown.append(std::string("No devices found: ") + error_buffer);
  } else {
      for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
          m_interface_dropdown.append(d->name);
      }
      pcap_freealldevs(alldevs); 
  }

  m_interface_dropdown.set_active(0); 
  m_interface_dropdown.signal_changed().connect(sigc::mem_fun(*this, &MyWindow::on_interface_selected));
  m_main_box.pack_start(m_interface_dropdown, Gtk::PACK_SHRINK);

  // promiscuous mode set up
  m_promiscuous_mode_check.set_active(false); // promiscous will be turned off at the beggining
  m_promiscuous_mode_check.signal_toggled().connect(sigc::mem_fun(*this, &MyWindow::on_promiscuous_mode_toggled));
  m_main_box.pack_start(m_promiscuous_mode_check, Gtk::PACK_SHRINK);

  add(m_main_box);
  show_all_children();
}

void MyWindow::on_interface_selected() {
  interface = m_interface_dropdown.get_active_text();  //ifs def
  handle = device.init_packet_capture(interface.c_str(), promiscuous_mode_enabled); 
  if (handle) {
    std::cout << "Packet capture started on interface: " << interface << std::endl;
  } else {
    std::cerr << "Failed to start packet capture on interface: " << interface << std::endl;
    std::cerr << "Error: " << device.error_buffer << std::endl;
  }
}



void MyWindow::on_promiscuous_mode_toggled() {
  promiscuous_mode_enabled = m_promiscuous_mode_check.get_active();
  std::cout << "Promiscuous mode " << (promiscuous_mode_enabled ? "enabled" : "disabled") << std::endl;
}


// Menu signal handlers
void MyWindow::on_menu_file_new() { std::cout << "New selected\n"; }
void MyWindow::on_menu_file_open() { std::cout << "Open selected\n"; }
void MyWindow::on_menu_file_exit() { hide(); }  

// Toolbar button handlers
void MyWindow::on_start_button_clicked() { std::cout << "Start capture\n"; /* Placeholder for starting sniffing*/ }
void MyWindow::on_stop_button_clicked() { std::cout << "Stop capture\n"; /* Placeholder for stopping sniffing */ }

// Filter option handlers
void MyWindow::on_filter_changed() {
  std::cout << "Filter updated\n";
  std::cout << "Source IP: " << m_source_entry.get_text() << std::endl;
  std::cout << "Destination IP: " << m_dest_entry.get_text() << std::endl;
  port_filter = m_port_entry.get_text();

  filter.netmask_lookup(interface, error_buffer);
  if (!handle) {
    std::cerr << "Invalid handle. Cannot set filter." << std::endl;
    return;
  }
  filter.filter_processing(handle, port_filter.c_str(), 0, filter.get_net());
}

pcap_t* MyWindow::get_handle() {
  return handle;
}


std::string MyWindow::get_interface(){
  return interface;
}
