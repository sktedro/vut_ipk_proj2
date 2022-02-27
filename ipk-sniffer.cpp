#include <pcap.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <string>
#include <bitset> // TODO remove

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>        // IPv4
#include <netinet/ip6.h>       // IPv6
#include <netinet/tcp.h>
#include <netinet/udp.h>
// #include <netinet/ip_icmp.h>
// #include <netinet/arp.h> // no need to include, it already is in ether.h

const int MAX_IP_LEN = 256;

const int TCP_N = 6;
const int UDP_N = 17;
const int ICMP_N = 1;


using namespace std;


void printData(const u_char *packet, int frameLen, int offset){

  // Start at the offset since we only want to print the data
  // TODO to frame len? There is something after the data, isn't there?
  for(int j = offset; j < frameLen; j += 16){

    // Print offset from the beginning of the data field in hex
    cout << "0x" << hex << setw(4) << j - offset << ": ";

    // Print bytes with spaces separating them in lowercase, while padding with
    // spaces if we reached the end of the frame before the end of line
    for(int k = j; k < j + 16; k++){
      if(k >= frameLen){
        cout << "  ";
      }else{
        cout << setw(2) << hex << (int)*(packet + k);
      }
      cout << " ";
    }

    // Print characters one by one (non-printable (up to ascii val 31) as '.')
    for(int k = j; k < j + 16 && k < frameLen; k++){
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
  // TODO:
  // string filter_expr = protocols_filter + " and " + port_filter;
  string filter_expr = protocols_filter;
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

    // Get the ethernet frame header and print MAC addresses
    const struct ether_header *eth_h = (struct ether_header*)(packet);
    cout << "src MAC: " << ether_ntoa((ether_addr *)eth_h->ether_shost) << endl;
    cout << "dst MAC: " << ether_ntoa((ether_addr *)eth_h->ether_dhost) << endl;
    
    // Print frame length
    cout << dec << "frame length: " << header.caplen << " bytes" << endl;

    // Set the offset after the ethernet header (fixed size of 14B)
    int offset = 14;

    // If the packet is of ARP protocol, IP and port are none
    if(eth_h->ether_type == 0x0806 || eth_h->ether_type == 0x0608){
      cout << "src IP:" << endl;
      cout << "dst IP:" << endl;
      cout << "src port:" << endl;
      cout << "dst port:" << endl;
      // TODO print data? There is none, so print the whole ARP message?

    }else{

      // Get the IP protocol version
      int version;
      if(eth_h->ether_type == 0x0800 || eth_h->ether_type == 0x0008){
        version = 4;
      }else if(eth_h->ether_type == 0x86dd || eth_h->ether_type == 0xdd86){
        version = 6;
      }else{
        cout << "Wrong IP protocol version" << endl;
        // TODO err?
      }

      // TODO remove
      cout << "IPv" << version << endl;

      // Get IP addrs and protocol used from the packet and increment the offset
      // (all using different ways for ipv4 and ipv6)
      char src_ip[MAX_IP_LEN];
      char dst_ip[MAX_IP_LEN];
      int protocol;
      if(version == 4){

        // Typecast to an IPv4 struct from netinet/ip.h library
        const struct ip *ip_h = (struct ip*)(packet + offset);

        // In IPv4, 'header_len' field specifies the number of 32b words in the
        // header, so we multiply by 4 to get the length in bytes
        offset += (int)(ip_h->ip_hl) * 4;

        // Convert the version 4 IPs to strings using arpa/inet.h library
        inet_ntop(AF_INET, &(ip_h->ip_src), src_ip, MAX_IP_LEN);
        inet_ntop(AF_INET, &(ip_h->ip_dst), dst_ip, MAX_IP_LEN);

        // Get the protocol number
        protocol = (int)ip_h->ip_p;

      }else if(version == 6){

        // Typecast to an IPv6 struct from netinet/ip6.h library
        const struct ip6_hdr *ip_h = (struct ip6_hdr*)(packet + offset);

        // IPv6 has a constant header length of 40B
        offset += 40; 

        // Convert the version 6 IPs to strings using arpa/inet.h library
        inet_ntop(AF_INET6, &(ip_h->ip6_src), src_ip, MAX_IP_LEN);
        inet_ntop(AF_INET6, &(ip_h->ip6_dst), dst_ip, MAX_IP_LEN);

        // Get the protocol number
        protocol = (int)ip_h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      }

      // Print the IP addresses
      cout << "src IP: " << src_ip << endl;
      cout << "dst IP: " << dst_ip << endl;

      // Print ports if TCP or UDP is used (ICMP doesn't use a port)
      // (they are at the same place for both tcp and udp protocols)
      if(protocol != ICMP_N){
        cout << "src port: " << (int)((short)*(packet + offset)) << endl;
        cout << "dst port: " << (int)((short)*(packet + offset + 2)) << endl;
      }else{
        cout << "src port:" << endl;
        cout << "dst port:" << endl;
      }


      // Skip the packet header
      if(protocol == TCP_N){

        // The amount of 32b words in TCP header is in 'Data offset' field
        offset += (int)((u_char)(*(packet + offset + 12)) >> 4 & 0b00001111);
        // TODO multiply by 4?

      // UDP and ICMP protocols have a fixed header size of 8B
      }else if(protocol == UDP_N || protocol == ICMP_N){
        offset += 8;
      }

      // Print the data (don't print last four bytes as it is the CRC) TODO but
      // should I really trim it??
      // printData(packet, (int)header.caplen, offset);
      printData(packet, (int)header.caplen - 4, offset);
      
      cout << endl;
    }
  }

  // Close the interface handle
  pcap_close(handle);

  return 0;
}

