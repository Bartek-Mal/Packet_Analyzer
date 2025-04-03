#ifndef PACKET_COLUMNS_H
#define PACKET_COLUMNS_H

#include <gtkmm.h>
#include <vector>
#include <cstdint>

class PacketColumns : public Gtk::TreeModelColumnRecord
{
public:
    PacketColumns()
    {
        add(col_packet_num);
        add(col_protocol);
        add(col_source);
        add(col_destination);
        add(col_info);
        add(col_color);

        // store entire packet data as a vector<uint8_t>
        add(col_raw_data);
    }

    Gtk::TreeModelColumn<int>                col_packet_num;
    Gtk::TreeModelColumn<Glib::ustring>      col_protocol;
    Gtk::TreeModelColumn<Glib::ustring>      col_source;
    Gtk::TreeModelColumn<Glib::ustring>      col_destination;
    Gtk::TreeModelColumn<Glib::ustring>      col_info;
    Gtk::TreeModelColumn<Glib::ustring>      col_color;

    // The raw packet bytes
    Gtk::TreeModelColumn< std::vector<uint8_t> > col_raw_data;
};

#endif // PACKET_COLUMNS_H
