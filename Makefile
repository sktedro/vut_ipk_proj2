

ALL:
	g++ -std=c++2a ipk-sniffer.cpp -o ipk-sniffer -lpcap -g -Wall -Wextra -Wno-unused-variable

run: ALL
	sudo ./ipk-sniffer -i wlo1 -p 80 -n 1

clean:
	rm -f ipk-sniffer
