/**
 * @brief A simple packet (frame) sniffer
 * @file ipk-sniffer.c
 * @author Patrik Skaloš
 * @year 2022
 */

// Standard libraries
#include <iomanip>
#include <iostream>
#include <getopt.h>
#include <string>
#include <csignal>
#include <bitset>

// Networking libraries
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

// Header files
#include "ipk-sniffer.h"


using namespace std;


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


/**
 * @brief Close tha interface handle after SIGINT (if it is open)
 *
 * @param sig (int)
 */
void sigint_handler(int sig){
  if(handle){
    pcap_close(handle);
  }
  exit(sig);
}


/**
 * @brief Print the string while applying indentation from the right
 * 
 * @param str (string)
 */
void print_with_indent(string str){
  cout << left << setfill(' ') << setw(DATA_INDENT) << str;
}


/**
 * @brief Print a MAC address according to a standard
 *
 * @param addr (const struct ether_addr)
 */
void print_mac(const struct ether_addr *addr){
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    addr->ether_addr_octet[0], addr->ether_addr_octet[1],
    addr->ether_addr_octet[2], addr->ether_addr_octet[3],
    addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
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
  while((opt = getopt_long(argc, argv, "i::p:tun:h", longOpts, nullptr)) != -1){
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
      case 'h':
        cout << usage;
        exit(0);
    }
  }

  return opts;
}


/**
 * @brief Print all available interfaces
 */
void printInterfaces(){

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
  add_filter_primitive(&protocolsFilter, opts.icmp, "icmp or icmp6", -1);

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
 * @brief Print all data of the frame in format:
 * offset, 16 characters in hex separated by a space, characters.
 * While offset is a four digit hex number followed by a colon and
 * non-printable characters are printed as dots
 *
 * @param frame (const u_char *, whole frame)
 * @param frameLen (int, total length of the frame)
 */
void print_data(const u_char *frame, int frameLen){

  cout << endl;
  for(int j = 0; j < frameLen; j += 16){

    // Print offset from the beginning of the data field in hex
    cout << "0x" << right << hex << setfill('0') << setw(4) << j << ": ";

    // Print bytes with spaces separating them one by one
    for(int k = j; k < j + 16; k++){

      // If in the middle (after 8 numbers), print an additional space
      if(k == j + 8){
        cout << " ";
      }

      // Pad with zeroes if the line is not full. Otherwise, just print the hex
      if(k >= frameLen){
        cout << "  ";
      }else{
        cout << setw(2) << hex << (int)*(frame + k);
      }
      cout << " ";
    }

    // Additional space between numbers and spaces
    cout << " ";

    // Print characters one by one
    for(int k = j; k < j + 16 && k < frameLen; k++){

      // If in the middle (after 8 numbers), print an additional space
      if(k == j + 8){
        cout << " ";
      }

      // Print the character from the frame (non-printable (ascii < 32) as '.')
      char c = (char)*(frame + k);
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
 * @brief Prints information about an IP packet (v4, v6) of protocols TCP, UDP
 * and ICMP - IP addresses and ports 
 *
 * @param frame (const u_char *, whole frame)
 * @param frameLen (int, total frame length)
 * @param version (int, IP protocol version)
 */
void parse_ip_packet(const u_char *frame, int offset, int version){

  char srcIp[INET6_ADDRSTRLEN];
  char dstIp[INET6_ADDRSTRLEN];
  int protocol;

  // Get IP addresses and protocol used from the frame and increment the offset
  // (all using different ways for v4 and v6)
  if(version == 4){

    // Typecast to an IPv4 struct from netinet/ip.h library
    const struct ip *ipv4_hdr = (struct ip*)(frame + offset);

    // In IPv4, 'header_len' field specifies the number of 32b words in the
    // header, so we multiply by 4 to get the length in bytes
    offset += (int)(ipv4_hdr->ip_hl) * 4;

    // Convert the version 4 IPs to strings using arpa/inet.h library
    inet_ntop(AF_INET, &(ipv4_hdr->ip_src), srcIp, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipv4_hdr->ip_dst), dstIp, INET6_ADDRSTRLEN);

    // Get the protocol number
    protocol = (int)ipv4_hdr->ip_p;

  }else if(version == 6){

    // Typecast to an IPv6 struct from netinet/ip6.h library
    const struct ip6_hdr *ipv6_hdr = (struct ip6_hdr*)(frame + offset);

    // IPv6 has a constant header length of 40B
    offset += 40; 

    // Convert the version 6 IPs to strings using arpa/inet.h library
    inet_ntop(AF_INET6, &(ipv6_hdr->ip6_src.s6_addr), srcIp, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_hdr->ip6_dst.s6_addr), dstIp, INET6_ADDRSTRLEN);

    // Get the protocol number
    protocol = (int)ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  }

  // Print the network layer protocol (IPv4 or IPv6 if it is not ICMP)
  print_with_indent("network layer proto: ");
  if(protocol == ICMPV4_N || protocol == ICMPV6_N){
    cout << "ICMPv" << version << endl;
  }else{
    cout << "IPv" << version << endl;
  }

  // Print the transport layer protocol if the network layer proto is not ICMP
  if(protocol == TCP_N){
    print_with_indent("transport layer proto: ");
    cout << "TCP" << endl;
  }else if(protocol == UDP_N){
    print_with_indent("transport layer proto: ");
    cout << "UDP" << endl;
  }

  // Print the source IP address
  print_with_indent("src IP: ");
  cout << srcIp << endl;

  // Print the destination IP address
  print_with_indent("dst IP: ");
  cout << dstIp << endl;

  // If it is an ICMP packet, read the first and second byte to print msg type 
  // and code (IP header was already parsed)
  if(protocol == ICMPV4_N || protocol == ICMPV6_N){

    // Print message type 
    print_with_indent("msg type: ");
    cout << dec << (int)*(uint8_t *)(frame + offset) << endl;

    // Print message code (sybtype)
    print_with_indent("msg code: ");
    cout << dec << (int)*(uint8_t *)(frame + offset + 1) << endl;

  // If it is not ICMP (is TCP or UDP segment), print ports - they are at the
  // same offset for both TCP and UDP
  // (ICMP doesn't use a port)
  }else{

    // Print the source port
    print_with_indent("src port: ");
    cout << dec << ntohs(*(unsigned short *)(frame + offset)) << endl;

    // Print the destination port
    print_with_indent("dst port: ");
    cout << dec << ntohs(*(unsigned short *)(frame + offset + 2)) << endl;

    // If the segment is TCP, also parse the TCP header and print relevant data
    // (there is no useful data for us in the UDP header other than the port)
    // (So, for TCP, print sequence and ack numbers and frames as bits)
    if(protocol == TCP_N){

      // Typecast to a TCP header structure
      const struct tcphdr *tcp_hdr = (struct tcphdr*)(frame + offset);

      // Print sequence number
      print_with_indent("seq number (raw): ");
      cout << dec << ntohl((int)tcp_hdr->th_seq) << endl;

      // Print ack number
      print_with_indent("ack number (raw): ");
      cout << dec << ntohl((int)tcp_hdr->th_ack) << endl;

      // Print flags as bits
      bitset<8> flags(tcp_hdr->th_flags);
      print_with_indent("flags as bits: ");
      cout << flags << endl;
    }
  }
}


/**
 * @brief Parse an ARP packet (print valuable information)
 *
 * @param frame (const u_char *, whole frame)
 * @param offset (int)
 */
void parse_arp_packet(const u_char *frame, int offset){

  // Typecast to a ARP packet structure
  const struct ether_arp *arp_hdr = (struct ether_arp *)(frame + offset);

  // Print the operation (request or reply)
  print_with_indent("operation: ");
  if(ntohs(arp_hdr->ea_hdr.ar_op) == 1){
    cout << "request" << endl;
  }else if(ntohs(arp_hdr->ea_hdr.ar_op) == 2){
    cout << "reply" << endl;
  }else{
    cout << "unknown: " << ntohs(arp_hdr->ea_hdr.ar_op) << endl;
  }

  // Print source MAC address
  print_with_indent("src MAC: ");
  print_mac((ether_addr *)arp_hdr->arp_sha);

  // Print source IP address
  char srcIp[MAX_IP_LEN];
  inet_ntop(AF_INET, &(arp_hdr->arp_spa), srcIp, MAX_IP_LEN);
  print_with_indent("src IP: ");
  cout << srcIp << endl;

  // Print target MAC address
  print_with_indent("tgt MAC: ");
  print_mac((ether_addr *)arp_hdr->arp_tha);

  // Print target IP address
  char dstIp[MAX_IP_LEN];
  inet_ntop(AF_INET, &(arp_hdr->arp_tpa), dstIp, MAX_IP_LEN);
  print_with_indent("tgt IP: ");
  cout << dstIp << endl;
}


/**
 * @brief Parse an ethernet frame received
 *
 * @param frame (const u_char *, whole frame)
 * @param frameLen (int)
 */
void parse_frame(const u_char *frame, int frameLen){

  // Get the ethernet frame header
  const struct ether_header *eth_hdr = (struct ether_header*)(frame);

  // Print the source MAC address
  print_with_indent("src MAC: ");
  print_mac((ether_addr *)eth_hdr->ether_shost);

  // Print the destination MAC address
  print_with_indent("dst MAC: ");
  print_mac((ether_addr *)eth_hdr->ether_dhost);
  
  // Print frame length
  print_with_indent("frame length: ");
  cout << dec << frameLen << " bytes" << endl;

  // Initialize the offset to 14 (fixed ethernet frame header length is 14B)
  int offset = 14;

  // The packet is of ARP protocol
  if(ntohs(eth_hdr->ether_type) == 0x0806){

    // Print the network layer protocol
    print_with_indent("network layer proto: ");
    cout << "ARP" << endl;

    // Print other meaningful information contained in the packet
    parse_arp_packet(frame, offset);


  // The packet is of IP or ICMP protocol - get the version and print more data
  }else{

    // Get the IP protocol version
    int version;
    if(ntohs(eth_hdr->ether_type) == 0x0800){
      version = 4;
    }else if(ntohs(eth_hdr->ether_type) == 0x86dd){
      version = 6;
    }

    // Print IP addresses, ports and data of an IP packet (v4, v6, ICMP)
    parse_ip_packet(frame, offset, version);
  }
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

  // If no interface was selected or the option wasn't even used, print all 
  // interfaces available
  if(!opts.interface){
    printInterfaces();
    return 0;
  }
  
  // Open the interface provided
  open_interface(opts.interface);

  // Create a filter expression (string) based on the options provided
  string filterExpr = get_filter_expr(opts);

  // Apply the created filter to the interface handle
  apply_filter(filterExpr);

  // Try to receive packetsAmount packets and print packet information after
  // receiving each one of them
  for(int i = 0; i < opts.packetsAmount; i++){

    // Grab a frame, ignore errors
    struct pcap_pkthdr header;
    const u_char *frame = pcap_next(handle, &header);
    if(!frame){
      cerr << "An error occured when grabbing a frame. Exiting" << endl;
      pcap_close(handle);
      return 1;
    }

    // Print the timestamp - YYYY-MM-DDThh:mm:ss.mmmZ
    print_with_indent("timestamp: ");
    cout << put_time(gmtime(&header.ts.tv_sec), "%FT%T") << '.' << right
      << setfill('0') << setw(6) << dec << header.ts.tv_usec << 'Z' << endl;

    // Parse the frame and print all valuable information. If 'false' is
    // returned, it means the packet was not processed nor printed
    parse_frame(frame, header.caplen);

    // Print the data no matter which protocol it was
    print_data(frame, header.caplen);

    cout << endl;
  }

  // Close the interface handle
  pcap_close(handle);

  return 0;
}
