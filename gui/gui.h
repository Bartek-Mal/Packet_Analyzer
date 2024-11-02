#ifndef GUI_H
#define GUI_H

#include <gtkmm.h>
#include <pcap.h>
#include "devices/devices.h"  
#include "filter/filter.h"

class MyWindow : public Gtk::Window
{
public:
  MyWindow();

private:
  void on_menu_file_new();
  void on_menu_file_open();
  void on_menu_file_exit();
  void on_start_button_clicked();
  void on_stop_button_clicked();
  void on_filter_changed();
  void on_interface_selected();        
  void on_promiscuous_mode_toggled();  
  pcap_t* get_handle();
  std::string get_interface();

  // Menu, toolbar, filters, and interface selection
  Gtk::Box m_main_box;
  Gtk::MenuBar m_menu_bar;
  Gtk::Toolbar m_toolbar;
  Gtk::ToolButton m_start_button;
  Gtk::ToolButton m_stop_button;
  Gtk::Box m_filter_box;
  Gtk::Label m_source_label;
  Gtk::Entry m_source_entry;
  Gtk::Label m_dest_label;
  Gtk::Entry m_dest_entry;
  Gtk::Label m_port_label;
  Gtk::Entry m_port_entry;
  Gtk::ComboBoxText m_interface_dropdown;
  Gtk::CheckButton m_promiscuous_mode_check;
  
  std::string interface;
  std::string port_filter;
  bool promiscuous_mode_enabled = false;

  // Pcap-related members
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  Devices device; 
  Filters filter;
  pcap_t* handle;
};

#endif // GUI_H
