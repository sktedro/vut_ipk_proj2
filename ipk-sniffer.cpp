#include <pcap.h>
#include <iomanip>
#include <iostream>
#include <getopt.h>
#include <string>

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
  char *interface = NULL;
  int port = -1;
  int tcp = 0, udp = 0, arp = 0, icmp = 0;
  int packetsAmount = 1;
};


/*
 * Global variables
 */


// Error buffer used by the pcap library
char errbuf[PCAP_ERRBUF_SIZE];


/*
 *
 * Functions
 *
 */


/*
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
  const struct option long_opts[] = {
    {"interface", optional_argument, 0,             'i'},
    {"tcp",       no_argument,       0,             't'},
    {"udp",       no_argument,       0,             'u'},
    {"arp",       no_argument,       &(opts.arp),  1},
    {"icmp",      no_argument,       &(opts.icmp), 1},
    {0, 0, 0, 0}
  };

  // Parse the provided options 
  int opt;
  while((opt = getopt_long(argc, argv, "i::p:tun:", long_opts, nullptr)) != -1){
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
  if(opts.interface == NULL){

    // Get the list and check for errors
    pcap_if_t *interfaces;
    if(pcap_findalldevs(&interfaces, errbuf) == -1){
      cerr << "Error in pcap_findalldevs_ex: " << errbuf << endl;
      exit(1);

    // Print it and free the memory
    }else{
      cout << "Interface list:" << endl;
      for(pcap_if_t *i = interfaces; i != NULL; i = i->next){
        cout << "  " << i->name << endl;
      }
      pcap_freealldevs(interfaces);
    }

    exit(0);
  }

  return opts;
}


/*
 * @brief Open an interface with name provided by an argument and return a
 * handle
 *
 * @param interface (char *)
 *
 * @return a handle to the interface
 */
pcap_t *open_interface(char *interface){

  // Open the interface
  pcap_t *handle = pcap_open_live(interface, BUFSIZ, true, 1000, errbuf);
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

  return handle;
}


/*
 * @brief Generates a string to filter the frames by (based on user options in
 * structure options)
 *
 * @param opts (struct options)
 *
 * @return a string containing the filtering expression
 * TODO
 */
string get_filter_string(struct options opts){

  // Port filter setting (eg. 'port 80')
  string port_filter = "port " + to_string(opts.port);

  // Protocol filter setting (eg. 'tcp or udp')
  string protocols_filter = "";
  if(opts.tcp + opts.udp + opts.arp + opts.icmp == 0){
    protocols_filter = "tcp or udp or arp or icmp";
  }else{
    if(opts.tcp){
      protocols_filter += "tcp";
      if(opts.udp || opts.arp || opts.icmp){
        protocols_filter += " or ";
      }
    }
    if(opts.udp){
      protocols_filter += "udp";
      if(opts.arp || opts.icmp){
        protocols_filter += " or ";
      }
    }
    if(opts.arp){
      protocols_filter += "arp";
      if(opts.icmp){
        protocols_filter += " or ";
      }
    }
    if(opts.icmp){
      protocols_filter += "icmp";
    }
  }

  // TODO:
  // return protocols_filter + " and " + port_filter;
  return protocols_filter;
}


/*
 * @brief Compiles and installs a filter
 *
 * @param filterExpr (string, containing the filter expression)
 */
void apply_filter(pcap_t *handle, string filterExpr){
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


/*
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


/*
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


/*
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

  // Add the packet header length to the offset variable
  if(protocol == TCP_N){

    // The amount of 32b words in TCP header is in 'Data offset' field
    const struct tcphdr *tcp_h = (struct tcphdr*)(packet + offset);
    offset += 4 * (int)(tcp_h->th_off);

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


// TODO print packet protocol
// TODO close interface handle after SIGINT
int main(int argc, char **argv){

  // Print usage if no arguments are provided
  if(argc == 1){
    cout << usage;
    return 0;
  }

  // Get all user options to a structure
  struct options opts = get_options(argc, argv);
  
  // Open the interface provided
  pcap_t *handle = open_interface(opts.interface);

  // Create a filter expression (string) based on the options provided
  string filterExpr = get_filter_string(opts);

  // Apply the created filter to the interface handle
  apply_filter(handle, filterExpr);

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
    const struct ether_header *eth_h = (struct ether_header*)(packet);
    cout << "src MAC: " << ether_ntoa((ether_addr *)eth_h->ether_shost) << endl;
    cout << "dst MAC: " << ether_ntoa((ether_addr *)eth_h->ether_dhost) << endl;
    
    // Print frame length
    cout << "frame length: " << header.caplen << " bytes" << endl;

    // The packet is of ARP protocol
    if(eth_h->ether_type == 0x0806 || eth_h->ether_type == 0x0608){

      // Print all data needed about an ARP packet
      print_arp_packet();

    // The packet is of IP protocol - get the version and print more data
    }else{
      int version;
      if(eth_h->ether_type == 0x0800 || eth_h->ether_type == 0x0008){
        version = 4;
      }else if(eth_h->ether_type == 0x86dd || eth_h->ether_type == 0xdd86){
        version = 6;
      }else{
        // If for some reason the version is not 4 nor 6, ignore this packet
        i--;
        continue;
      }

      // Print IP addresses, ports and data of an IP packet
      print_ip_packet(packet, (int)header.caplen, version);
    }

    cout << endl;
  }

  // Close the interface handle
  pcap_close(handle);

  return 0;
}

