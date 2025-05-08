#include "devices.h"

Devices::Devices() {
}

Devices::~Devices() {
}

pcap_t* Devices::init_packet_capture(const char* interface, bool promiscuous){
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, promiscuous, 1000, this->error_buffer);

    if (handle == nullptr){
         std::cout << "Nie można otworzyć urządzenia: " << this->error_buffer << std::endl;
        return nullptr;
    }
    else{
        std::cout << "Sesja otwarta dla interfejsu:" << interface<< std::endl;
        return handle;
    }
        
}

