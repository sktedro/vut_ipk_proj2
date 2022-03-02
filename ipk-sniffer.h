/**
 * @brief A simple packet (frame) sniffer
 * @file ipk-sniffer.h
 * @author Patrik Skaloš
 * @year 2022
 */


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

// When displayin data, this is the amount of characters for the 'title'
// eg. 'timestamp:----fill-----2022...'
const int DATA_INDENT = 25;

// Usage string
const string usage = "Usage:\n\
\n\
./ipk-sniffer [-h] [-i int] [-p port] [--tcp] [--udp] [--arp] [--icmp] [-n num]\n\
\n\
Options:\n\
  -h print this help\n\
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
 *
 * Functions
 *
 */


/**
 * @brief Close tha interface handle after SIGINT (if it is open)
 *
 * @param sig (int)
 */
void sigint_handler(int sig);

/**
 * @brief Print the string while applying indentation from the right
 *
 * @param str (string)
 */
void print_with_indent(string str);

/**
 * @brief Print a MAC address according to a standard
 *
 * @param addr (const struct ether_addr)
 */
void print_mac(const struct ether_addr *addr);

/**
 * @brief Parse user provided options to a structure
 * 
 * @param argc
 * @param argv
 *
 * @return struct options
 */
struct options get_options(int argc, char **argv);

/**
 * @brief Print all available interfaces
 */
void printInterfaces();

/**
 * @brief Open an interface with name provided by an argument and return a
 * handle
 *
 * @param interface (char *)
 *
 * @return a handle to the interface
 */
void open_interface(char *interface);

/**
 * @brief A helper function to add a filter primitive to a string expression
 *
 * @param expr (string *, the expression built so far)
 * @param enabled (int, from struct options to say if the protocol is enabled)
 * @param str (string, the protocol name)
 * @param port (int, from struct options, -1 if none is selected)
 */
void add_filter_primitive(string *expr, int enabled, string str, int port);

/**
 * @brief Generates a string to filter the frames by (based on user options in
 * structure options)
 *
 * @param opts (struct options)
 *
 * @return a string containing the filtering expression
 */
string get_filter_expr(struct options opts);

/**
 * @brief Compiles and installs a filter
 *
 * @param filterExpr (string, containing the filter expression)
 */
void apply_filter(string filterExpr);

/**
 * @brief Print all data of the frame in format:
 * offset, 16 characters in hex separated by a space, characters.
 * While offset is a four digit hex number followed by a colon and
 * non-printable characters are printed as dots
 *
 * @param frame (const u_char *, whole frame)
 * @param frameLen (int, total length of the frame)
 */
void print_data(const u_char *frame, int frameLen);

/**
 * @brief Prints information about an IP packet (v4, v6) of protocols TCP, UDP
 * and ICMP - IP addresses and ports 
 *
 * @param frame (const u_char *, whole frame)
 * @param frameLen (int, total frame length)
 * @param version (int, IP protocol version)
 */
void parse_ip_packet(const u_char *frame, int offset, int version);

/**
 * @brief Parse an ARP packet (print valuable information)
 *
 * @param frame (const u_char *, whole frame)
 * @param offset (int)
 */
void parse_arp_packet(const u_char *frame, int offset);

/**
 * @brief Parse an ethernet frame received
 *
 * @param frame (const u_char *, whole frame)
 * @param frameLen (int)
 */
void parse_frame(const u_char *frame, int frameLen);
