#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include "pcapanalyze.h"


void process_pcap(std::string filename) {
   std::ifstream pcap_file(filename, std::ios::binary);
   if(pcap_file.is_open()) {
       std::cout << "open' " + filename + " 'success" << std::endl;
       //pcap头部24字节（0-23）
       pcap_file.seekg(24);//skip the header(24 bytes)

   } else {
       std::cout << "open' " + filename + " 'fail" << std::endl;
   }
}

int main() {



    std::cout << "Processing!!!" << std::endl;
    process_pcap("test.pcap");
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
