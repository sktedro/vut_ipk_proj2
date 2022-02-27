/**
 * @brief A simple packet (frame) sniffer
 * @author Patrik Skaloš
 * @year 2022
 */


// Standard libraries
#include <pcap.h>
#include <iomanip>
#include <iostream>
#include <getopt.h>
#include <string>
#include <csignal>

// Networking libraries
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>        // IPv4
#include <netinet/ip6.h>       // IPv6
#include <netinet/tcp.h>


using namespace std;


/*
 * Constants
 */


// Maximum IP address length in chars
const int MAX_IP_LEN = 32;

// Numbers identifying protocols in headers
const int TCP_N = 6;
const int UDP_N = 17;
const int ICMP_N = 1;

// Usage string
const string usage = "Usage:\n\
\n\
./ipk-sniffer [-i int] {-p port} {[--tcp] [--udp] [--arp] [--icmp]} {-n num}\n\
\n\
Options:\n\
  -i interface to sniff on\n\
  -p port to use\n\
  --tcp, --udp, --icmp, --arp select protocols to filter the traffic by. If\n\
    none is used, all four protocols are selected by default\n\
  -n amount of packets to stop after\n";


/*
 * Structures
 */


// A structure containing all user-provided options
struct options{
  char *interface = nullptr;
  int port = -1;
  int tcp = 0, udp = 0, arp = 0, icmp = 0;
  int packetsAmount = 1;
};


/*
 * Global variables
 */


// Error buffer used by the pcap library
char errbuf[PCAP_ERRBUF_SIZE];

// Interface handle (needs to be global to exit safely after SIGINT)
pcap_t *handle = nullptr;


/*
 *
 * Functions
 *
 */


void sigint_handler(int sig){
  if(handle){
    pcap_close(handle);
  }
  exit(sig);
}

/**
 * @brief Parse user provided options to a structure
 * 
 * @param argc
 * @param argv
 *
 * @return struct options
 */
struct options get_options(int argc, char **argv){
  struct options opts;

  // Long options definition
  const struct option longOpts[] = {
    {"interface", optional_argument, 0,             'i'},
    {"tcp",       no_argument,       0,             't'},
    {"udp",       no_argument,       0,             'u'},
    {"arp",       no_argument,       &(opts.arp),   1},
    {"icmp",      no_argument,       &(opts.icmp),  1},
    {0, 0, 0, 0}
  };

  // Parse the provided options 
  int opt;
  while((opt = getopt_long(argc, argv, "i::p:tun:", longOpts, nullptr)) != -1){
    switch (opt){
      case 'i':
        if(optind < argc && argv[optind][0] != '-'){
          opts.interface = argv[optind];
        }
        break;
      case 'p':
        opts.port = stoi(optarg);
        break;
      case 't':
        opts.tcp = 1;
        break;
      case 'u':
        opts.udp = 1;
        break;
      case 'n':
        opts.packetsAmount = stoi(optarg);
        break;
    }
  }

  // If no interface was selected or the option wasn't used, print all available
  if(opts.interface == nullptr){

    // Get the list and check for errors
    pcap_if_t *interfaces;
    if(pcap_findalldevs(&interfaces, errbuf) == -1){
      cerr << "Error in pcap_findalldevs_ex: " << errbuf << endl;
      exit(1);

    // Print it and free the memory
    }else{
      cout << "Interface list:" << endl;
      for(pcap_if_t *i = interfaces; i != nullptr; i = i->next){
        cout << "  " << i->name << endl;
      }
      pcap_freealldevs(interfaces);
    }

    exit(0);
  }

  return opts;
}


/**
 * @brief Open an interface with name provided by an argument and return a
 * handle
 *
 * @param interface (char *)
 *
 * @return a handle to the interface
 */
void open_interface(char *interface){

  // Open the interface (and save the handle to a global variable)
  handle = pcap_open_live(interface, BUFSIZ, true, 1000, errbuf);
  if(!handle) {
    cerr << "Couldn't open interface " << interface << ". Error message: " 
      << errbuf << endl;
    exit(1);
  }

  // Check if the interface works with ethernet headers
  if (pcap_datalink(handle) != DLT_EN10MB) {
    cerr << "Interface '" << interface << "' is not supported" << endl;
    pcap_close(handle);
    exit(1);
  }
}


/**
 * @brief A helper function to add a filter primitive to a string expression
 *
 * @param expr (string *, the expression built so far)
 * @param enabled (int, from struct options to say if the protocol is enabled)
 * @param str (string, the protocol name)
 * @param port (int, from struct options, -1 if none is selected)
 */
void add_filter_primitive(string *expr, int enabled, string str, int port){
  static bool includeOr = false;

  // Do nothing if the protocol is not enabled
  if(enabled){

    // Only include 'or' if this is not the first primitive
    if(includeOr){
      *expr += " or ";
    }
    includeOr = true;

    // If port is defined, eg. '(tcp and port 80)' instead of 'tcp'
    if(port != -1){
      *expr += "(" + string(str) + " and port " + to_string(port) + ")";
    }else{
      *expr += string(str);
    }
  }
}


/**
 * @brief Generates a string to filter the frames by (based on user options in
 * structure options)
 *
 * @param opts (struct options)
 *
 * @return a string containing the filtering expression
 */
string get_filter_expr(struct options opts){

  // If no option is selected, manually select all
  if(opts.tcp + opts.udp + opts.arp + opts.icmp == 0){
    opts.tcp = opts.udp = opts.arp = opts.icmp = 1;
  }

  // Protocol filter setting (eg. '(tcp and port 80) or icmp')
  string protocolsFilter = "";
  add_filter_primitive(&protocolsFilter, opts.tcp,  "tcp",  opts.port);
  add_filter_primitive(&protocolsFilter, opts.udp,  "udp",  opts.port);
  add_filter_primitive(&protocolsFilter, opts.arp,  "arp",  opts.port);
  add_filter_primitive(&protocolsFilter, opts.icmp, "icmp", -1);

  return protocolsFilter;
}


/**
 * @brief Compiles and installs a filter
 *
 * @param filterExpr (string, containing the filter expression)
 */
void apply_filter(string filterExpr){
  struct bpf_program filter;

  // Compile the filter
  if (pcap_compile(handle, &filter, &filterExpr[0], 0, 0) == -1) {
    cerr << "Couldn't parse filter: " << filterExpr << ". Error message: "
      << pcap_geterr(handle) << endl;
    pcap_close(handle);
    exit(1);
  }

  // Install the filter
  if (pcap_setfilter(handle, &filter) == -1) {
    cerr << "Couldn't install filter: " << filterExpr << ". Error message: "
      << pcap_geterr(handle) << endl;
    pcap_close(handle);
    exit(1);
  }
}


/**
 * @brief Print all data of packet from the offset to the end in format:
 * offset, 16 characters in hex separated by a space, characters.
 * While offset is a four digit hex number followed by a colon and
 * non-printable characters are printed as dots
 *
 * @param packet (const u_char *)
 * @param frameLen (int, total length of the frame)
 * @param offset (int, offset from the start of the packet to the data field)
 */
void print_data(const u_char *packet, int frameLen, int offset){

  // Start at the offset since we only want to print the data
  cout << endl;
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


/**
 * @brief Prints information about an ARP packet (none needs to be printed so
 * it prints none)
 */
void print_arp_packet(){
  cout << "src IP:" << endl;
  cout << "dst IP:" << endl;
  cout << "src port:" << endl;
  cout << "dst port:" << endl;
  // TODO print data? There is none, so print the whole ARP message?
}


/**
 * @brief Prints information about an IP packet (TCP, UDP or ICMP) - IP
 * addresses, ports and calls print_data() function to print all the
 * encapsulated data
 *
 * @param packet (const u_char *)
 * @param frameLen (int, total frame length)
 * @param version (int, IP protocol version)
 */
void print_ip_packet(const u_char *packet, int frameLen, int version){

  // Continue reading after the ethernet header (fixed size of 14B)
  int offset = 14;

  // Get IP addresses and protocol used from the packet and increment the offset
  // (all using different ways for ipv4 and ipv6)
  char srcIp[MAX_IP_LEN];
  char dstIp[MAX_IP_LEN];
  int protocol;
  if(version == 4){

    // Typecast to an IPv4 struct from netinet/ip.h library
    const struct ip *ipv4_hdr = (struct ip*)(packet + offset);

    // In IPv4, 'header_len' field specifies the number of 32b words in the
    // header, so we multiply by 4 to get the length in bytes
    offset += (int)(ipv4_hdr->ip_hl) * 4;

    // Convert the version 4 IPs to strings using arpa/inet.h library
    inet_ntop(AF_INET, &(ipv4_hdr->ip_src), srcIp, MAX_IP_LEN);
    inet_ntop(AF_INET, &(ipv4_hdr->ip_dst), dstIp, MAX_IP_LEN);

    // Get the protocol number
    protocol = (int)ipv4_hdr->ip_p;

  }else if(version == 6){

    // Typecast to an IPv6 struct from netinet/ip6.h library
    const struct ip6_hdr *ipv6_hdr = (struct ip6_hdr*)(packet + offset);

    // IPv6 has a constant header length of 40B
    offset += 40; 

    // Convert the version 6 IPs to strings using arpa/inet.h library
    inet_ntop(AF_INET6, &(ipv6_hdr->ip6_src), srcIp, MAX_IP_LEN);
    inet_ntop(AF_INET6, &(ipv6_hdr->ip6_dst), dstIp, MAX_IP_LEN);

    // Get the protocol number
    protocol = (int)ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  }

  // Print the transport layer protocol
  if(protocol == TCP_N){
    cout << "Transport layer protocol: TCP" << endl;
  }else if(protocol == UDP_N){
    cout << "Transport layer protocol: UDP" << endl;
  }else if(protocol == ICMP_N){
    cout << "Transport layer protocol: ICMP" << endl;
  }

  // Print the IP addresses
  cout << "src IP: " << srcIp << endl;
  cout << "dst IP: " << dstIp << endl;

  // Print ports if TCP or UDP is used (ICMP doesn't use a port)
  // (they are at the same place for both tcp and udp protocols)
  if(protocol != ICMP_N){
    cout << "src port: " << (int)((short)*(packet + offset)) << endl;
    cout << "dst port: " << (int)((short)*(packet + offset + 2)) << endl;
  }else{
    cout << "src port:" << endl;
    cout << "dst port:" << endl;
  }

  // Add the packet header length to the offset variable
  if(protocol == TCP_N){

    // The amount of 32b words in TCP header is in 'Data offset' field
    const struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + offset);
    offset += 4 * (int)(tcp_hdr->th_off);

  }else if(protocol == UDP_N || protocol == ICMP_N){

    // UDP and ICMP protocols have a fixed header size of 8B
    offset += 8;
  }

  // Print the data
  print_data(packet, frameLen, offset);
}


/*
 *
 * Main
 *
 */


int main(int argc, char **argv){

  // Print usage if no arguments are provided
  if(argc == 1){
    cout << usage;
    return 0;
  }

  // Register a signal handler for SIGINT
  signal(SIGINT, sigint_handler);

  // Get all user options to a structure
  struct options opts = get_options(argc, argv);
  
  // Open the interface provided
  open_interface(opts.interface);

  // Create a filter expression (string) based on the options provided
  string filterExpr = get_filter_expr(opts);

  // Apply the created filter to the interface handle
  apply_filter(filterExpr);

  // Try to receive packetsAmount packets and print packet information after
  // receiving each one of them
  for(int i = 0; i < opts.packetsAmount; i++){

    // Grab a packet
    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(handle, &header);

    // Print the timestamp
    time_t tmp = header.ts.tv_sec;
    cout << "timestamp: " << put_time(gmtime(&tmp), "%FT%T") << '.' 
      << setfill('0') << setw(3) << 'Z' << endl;

    // Get the ethernet frame header and print MAC addresses
    const struct ether_header *eth_hdr = (struct ether_header*)(packet);
    cout << "src MAC: " << ether_ntoa((ether_addr *)eth_hdr->ether_shost) << endl;
    cout << "dst MAC: " << ether_ntoa((ether_addr *)eth_hdr->ether_dhost) << endl;
    
    // Print frame length
    cout << "frame length: " << header.caplen << " bytes" << endl;

    // The packet is of ARP protocol
    if(eth_hdr->ether_type == 0x0806 || eth_hdr->ether_type == 0x0608){

      // Print the network layer protocol
      cout << "Network layer protocol: ARP" << endl;

      // Print all data needed about an ARP packet
      print_arp_packet();

    // The packet is of IP protocol - get the version and print more data
    }else{
      int version;
      if(eth_hdr->ether_type == 0x0800 || eth_hdr->ether_type == 0x0008){
        version = 4;
      }else if(eth_hdr->ether_type == 0x86dd || eth_hdr->ether_type == 0xdd86){
        version = 6;
      }else{
        // If for some reason the version is not 4 nor 6, ignore this packet
        i--;
        continue;
      }

      // Print the network layer protocol
      cout << "Network layer protocol: IPv" << version << endl;

      // Print IP addresses, ports and data of an IP packet
      print_ip_packet(packet, (int)header.caplen, version);
    }

    cout << endl;
  }

  // Close the interface handle
  pcap_close(handle);

  return 0;
}

