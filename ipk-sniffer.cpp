#include <pcap.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <string>

using namespace std;

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
    printf("Got a packet with length of [%d]\n", header.len); // TODO

    // Print the timestamp
    time_t tmp = header.ts.tv_sec;
    cout << "timestamp: " << put_time(gmtime(&tmp ), "%FT%T") << '.' 
      << setfill('0') << setw(3) << 'Z' << endl;

    // Get IP protocol version
    /*
     * char version[5];
     * for(int j = 0; j < 4; j++){
     *   version[j] = packet[j];
     * }
     * version[5] = '\0';
     * cout << "<" << version << ">" << endl;
     */

  }

  // Close the interface handle
  pcap_close(handle);

  return 0;
}
