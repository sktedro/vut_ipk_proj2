NAME=ipk-sniffer

ALL:
	g++ -std=c++2a $(NAME).cpp -o $(NAME) -lpcap -g -Wall -Wextra -Wno-unused-variable

run: ALL
	sudo ./$(NAME) -i wlo1 -p 80 -n 1

clean:
	rm -f $(NAME)
