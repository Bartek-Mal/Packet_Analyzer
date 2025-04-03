#ifndef DETAIL_WINDOW_H
#define DETAIL_WINDOW_H

#include <gtkmm.h>
#include <vector>
#include <cstdint>
#include <string>

/**
 * DetailWindow: a simple window that displays detailed info for a single packet:
 * - protocol, source, dest, info (from the row)
 * - a hex dump of the raw packet bytes
 */
class DetailWindow : public Gtk::Window
{
public:
    DetailWindow(const std::vector<uint8_t>& raw_data,
                 const Glib::ustring& protocol,
                 const Glib::ustring& source,
                 const Glib::ustring& destination,
                 const Glib::ustring& info);
    virtual ~DetailWindow();

private:
    Gtk::VBox m_main_box;
    Gtk::TextView m_text_view;
    Glib::RefPtr<Gtk::TextBuffer> m_text_buffer;
};

#endif // DETAIL_WINDOW_H
