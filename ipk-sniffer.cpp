#include <pcap.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <string>
#include <bitset> // TODO remove

using namespace std;

// Ethernet frame header structure
const int ETH_HEADER_LEN = 14; // Ethernet header is 14B long
const int ETH_HEADER_ADDR_LEN = 6; // 48b (6B) for a MAC address
const int ETH_HEADER_TYPE_LEN = 2; // 2B for the ether type
struct eth_header{
  u_char dst_addr[ETH_HEADER_ADDR_LEN];
  u_char src_addr[ETH_HEADER_ADDR_LEN];
  u_char ether_type[ETH_HEADER_TYPE_LEN];
};

// IPv4 packet header structure
struct ipv4_header{
  u_char version_and_header_len;
  u_char tos;
  short total_len;
  short id;
  short flags_and_fragment_offset;
  u_char ttl;
  u_char proto;
  short header_checksum;
  u_char src_addr[4];
  u_char dst_addr[4];
};

// IPv6 packet header structure
struct ipv6_header{
  short version_and_tc_and_flow_label;
  short total_len;
  u_char next_header;
  u_char hop_limit;
  u_char src_addr[16];
  u_char dst_addr[16];
};

void print_mac_addr(string label, const u_char *mac){
  cout << label;
  for(int i = 0; i < ETH_HEADER_ADDR_LEN; i++){
    if(i > 0){
      cout << ":";
    }
    cout << setw(2) << hex << (int)mac[i];
  }
  cout << endl;
}

void print_ipv4_addr(string label, const u_char *ip){
  cout << label;
  for(int i = 0; i < 4; i++){ // IPv4 has 4B long addresses
    if(i > 0){
      cout << ".";
    }
    cout << (int)ip[i];
  }
  cout << endl;
}

void print_ipv6_addr(string label, const u_char *ip){
  cout << label;
  for(int i = 0; i < 16; i++){ // IPv6 has 16B long addresses
    if(i > 0 && i % 2 == 0){
      cout << ":";
    }
    cout << hex << (int)ip[i];
  }
  cout << endl;
}


int main(int argc, char **argv){

  // Error buffer used by the pcap library
  char errbuf[PCAP_ERRBUF_SIZE];

  // Init variables set by the user using run options
  char *interface = NULL;
  int port = -1; // -1 means all ports
  int tcp = 0, udp = 0, arp = 0, icmp = 0;
  int packets_amount = 1;

  // Long options definition
  const struct option long_opts[] = {
    {"interface", optional_argument, 0,     'i'},
    {"tcp",       no_argument,       0,     't'},
    {"udp",       no_argument,       0,     'u'},
    {"arp",       no_argument,       &arp,  1},
    {"icmp",      no_argument,       &icmp, 1},
    {0, 0, 0, 0}
  };

  // Parse the provided options 
  int opt;
  while((opt = getopt_long(argc, argv, "i::p:tun:", long_opts, nullptr)) != -1){
    switch (opt){
      case 'i':
        if(optind < argc && argv[optind][0] != '-'){
          interface = argv[optind];
        }
        break;
      case 'p':
        port = stoi(optarg);
        break;
      case 't':
        tcp = 1;
        break;
      case 'u':
        udp = 1;
        break;
      case 'n':
        packets_amount = stoi(optarg);
        break;
      default:
        cout << "Usage placeholder" << endl; // TODO
    }
  }

  // If no interface was selected or the option wasn't used, print all available
  // Inspired by: https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut1.html
  if(interface == NULL){

    // Get the list and check for errors
    pcap_if_t *interfaces;
    if(pcap_findalldevs(&interfaces, errbuf) == -1){
      cerr << "Error in pcap_findalldevs_ex: " << errbuf << endl;
      return 1;

    // Print it and free the memory
    }else{
      cout << "Interface list:" << endl;
      for(pcap_if_t *i = interfaces; i != NULL; i = i->next){
        cout << "  " << i->name << endl;
      }
      pcap_freealldevs(interfaces);
      return 0;
    }
  }

  // Print init info
  cout << "Starting monitoring interface '" << interface << "' on port '"
    << port << "' for '" << packets_amount << "' packets" << endl;

  // Open the interface
  pcap_t *handle = pcap_open_live(interface, BUFSIZ, true, 1000, errbuf);
  if(!handle) {
    cerr << "Couldn't open interface " << interface << ". Error message: " 
      << errbuf << endl;
    return 1;
  }

  // Check if the interface works with ethernet headers
  if (pcap_datalink(handle) != DLT_EN10MB) {
    cerr << "Interface '" << interface << "' is not supported" << endl;
    return 1;
  }

  // Protocol filter setting (eg. 'tcp or udp')
  string protocols_filter = "";
  if(tcp + udp + arp + icmp == 0){
    protocols_filter = "tcp or udp or arp or icmp";
  }else{
    if(tcp){
      protocols_filter += "tcp";
      if(udp || arp || icmp){
        protocols_filter += " or ";
      }
    }
    if(udp){
      protocols_filter += "udp";
      if(arp || icmp){
        protocols_filter += " or ";
      }
    }
    if(arp){
      protocols_filter += "arp";
      if(icmp){
        protocols_filter += " or ";
      }
    }
    if(icmp){
      protocols_filter += "icmp";
    }
  }

  // Port filter setting (eg. 'port 80')
  string port_filter = "port " + to_string(port);


  // Create a filter, compile it and install it to the handle
  string filter_expr = protocols_filter + " and " + port_filter;
  struct bpf_program filter;
  if (pcap_compile(handle, &filter, &filter_expr[0], 0, 0) == -1) {
    cerr << "Couldn't parse filter: " << filter_expr << ". Error message: "
      << pcap_geterr(handle) << endl;
    return 1;
  }
  if (pcap_setfilter(handle, &filter) == -1) {
    cerr << "Couldn't install filter: " << filter_expr << ". Error message: "
      << pcap_geterr(handle) << endl;
    return 1;
  }


  // Try to receive packets_amount packets and print packet information after
  // receiving each one of them
  struct pcap_pkthdr header;
  const u_char *packet;	
  for(int i = 0; i < packets_amount; i++){

    // Grab a packet
    packet = pcap_next(handle, &header);

    // Print the timestamp
    time_t tmp = header.ts.tv_sec;
    cout << "timestamp: " << put_time(gmtime(&tmp ), "%FT%T") << '.' 
      << setfill('0') << setw(3) << 'Z' << endl;

    // Get the ethernet (frame) header by typecasting received frame to a struct
    const struct eth_header *eth_h = (struct eth_header*)(packet);

    // Print the MAC addresses
    print_mac_addr("src MAC: ", eth_h->src_addr);
    print_mac_addr("dst MAC: ", eth_h->dst_addr);

    // Print frame length
    cout << dec << "frame length: " << (int)header.len << " bytes" << endl;
    // TODO that's not frame len lol


    // Get the packet header (IP protocol)
    int offset = ETH_HEADER_LEN;
    int protocol;

    // To get the version, get the first 8 bits of the packet header, shift to
    // the right by 4 bits since the version is 4 bits long and convert to int
    const int version = (int)((u_char)(*(packet + offset)) >> 4);
    if(version == 4){
      const struct ipv4_header *ip_h = (struct ipv4_header*)(packet + offset);

      // header_len in ipv4 contains 4 bits that specify the number of 32-bit 
      // words in the header, so we multiply by 4 to get the length in bytes
      const int header_len = (int)(ip_h->version_and_header_len & 0b1111) * 4;
      offset += header_len;

      print_ipv4_addr("src IP: ", ip_h->src_addr);
      print_ipv4_addr("dst IP: ", ip_h->dst_addr);

      protocol = (int)ip_h->proto;

    }else if(version == 6){
      const struct ipv6_header *ip_h = (struct ipv6_header*)(packet + offset);

      const int header_len = 40; // ipv6 has a constant header length of 40B
      offset += header_len;

      print_ipv6_addr("src IP: ", ip_h->src_addr);
      print_ipv6_addr("dst IP: ", ip_h->dst_addr);

      protocol = (int)ip_h->next_header;

      // TODO else ICMP, ARP?
    }else{
      // TODO something went wrong
    }

    // Print ports (they are at the same place for both tcp and udp protocols)

    int src_port = (int)((short)*(packet + offset));
    cout << "src port: " << src_port << endl;

    int dst_port = (int)((short)*(packet + offset + 2));
    cout << "dst port: " << dst_port << endl;

    // TCP header length in 4B unit is specified by 'Data offset' field
    if(protocol == 6){
      offset += (int)((u_char)(*(packet + offset + 12)) >> 4 & 0b00001111);

    // UDP protocol has a fixed header size of 8B
    }else if(protocol == 17){
      offset += 8;
    }



    // Print data
    for(int j = offset; j < (int)header.len; j += 16){

      // Print offset in data in hex (not 'offset', but 'j')

      cout << "0x" << hex << setw(4) << j - offset << ": ";
      // Print bytes with spaces separating them in lowercase
      for(int k = j; k < j + 16; k++){
        // If we reached the end, pad the rest of the line with spaces
        if(k >= (int)header.len){
          cout << "  ";
        }else{
          cout << setw(2) << hex << (int)*(packet + k);
        }
        cout << " ";
      }

      // Print characters one by one (non-printable (up to ascii val 31) as '.')
      for(int k = j; k < j + 16 && k < (int)header.len; k++){
        char c = (char)*(packet + k);
        if(c < 32){
          cout << ".";
        }else{
          cout << c;
        }
      }

      cout << endl;
    }
  }

  // Close the interface handle
  pcap_close(handle);

  return 0;
}
