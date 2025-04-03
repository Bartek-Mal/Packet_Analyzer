#include "detail_window.h"
#include <iomanip>
#include <sstream>

DetailWindow::DetailWindow(const std::vector<uint8_t>& raw_data,
                           const Glib::ustring& protocol,
                           const Glib::ustring& source,
                           const Glib::ustring& destination,
                           const Glib::ustring& info)
{
    set_title("Packet Details");
    set_default_size(600, 400);

    add(m_main_box);

    m_text_buffer = Gtk::TextBuffer::create();
    m_text_view.set_buffer(m_text_buffer);

    // Build a string with general info + a hex dump
    std::ostringstream oss;
    oss << "Protocol: "   << protocol    << "\n"
        << "Source:   "   << source      << "\n"
        << "Dest:     "   << destination << "\n"
        << "Info:     "   << info        << "\n\n"
        << "Hex Dump (length=" << raw_data.size() << " bytes):\n";

    // Format: offset + 16 bytes in hex
    const size_t bytes_per_line = 16;
    for(size_t i = 0; i < raw_data.size(); i++)
    {
        if(i % bytes_per_line == 0) {
            oss << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        }

        oss << std::setw(2) << std::setfill('0') << std::hex
            << static_cast<unsigned>(raw_data[i]) << " ";

        if((i+1) % bytes_per_line == 0) {
            oss << "\n";
        }
    }
    // If the last line wasn't complete, add a line break
    if(raw_data.size() % bytes_per_line != 0) {
        oss << "\n";
    }

    m_text_buffer->set_text(oss.str());
    m_main_box.pack_start(m_text_view, Gtk::PACK_EXPAND_WIDGET);

    show_all_children();
}

DetailWindow::~DetailWindow()
{
}
