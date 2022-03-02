# Brief

This is a simple packet sniffer capable of capturing frames on one interface
while allowing filtering by port number. It can capture frames of TCP, UDP, ARP
and ICMP protocols and user options allow for filtering any combination of these
protocols. It is written in C++.


# Author

Patrik Skaloš


# Usage

`./ipk-sniffer [-h] [-i int] [-p port] [--tcp] [--udp] [--arp] [--icmp] [-n
num]`

`-h` print this help \
`-i` interface to sniff on \
`-p` port to use \
`--tcp`, `--udp`, `--icmp`, `--arp` select protocols to filter the traffic by. 
  If none is used, all four protocols are selected by default \
`-n` amount of packets to stop after \ 

Note: Program may require root privileges

### Examples

#### Print usage

`./ipk-sniffer -h`

#### Print all available interfaces

`./ipk-sniffer -i`

#### Listen on interface wlo1 for four TCP frames

`./ipk-sniffer -i wlo1 --tcp -n 4`

#### Listen on interface wlo1 for any one frame on port 80

`./ipk-sniffer -i wlo1 -p 80`

or

`./ipk-sniffer -i wlo1 -p 80 --tcp --udp --arp --icmp`

#### Listen on interface wlo1 for an ICMP frame or  UDP frame on port 80

`./ipk-sniffer -i wlo1 -p 80 --udp --icmp`


# Notes

#### Libraries

The code requires some standard libraries along with `arpa/inet` and several
`netinet` libraries.

#### Kill command

The sniffer can be safely killed using `SIGINT` signal (Ctrl+C). Using any other
signal might result in an interface handle not being closed.


# Documentation

For more information about this project (including introduction, references
and such), check out the documentation in `doc/` folder.
