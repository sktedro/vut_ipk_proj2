NAME=ipk-sniffer

ALL:
	g++ -std=c++2a $(NAME).cpp -o $(NAME) -lpcap -Wall -Wextra

run: ALL
	@sudo ./$(NAME) -i wlo1 -n 1

pack: clean
	make -C doc/ 
	cp doc/doc.pdf ./manual.pdf
	tar -cf xskalo01.tar $(NAME).cpp $(NAME).h Makefile manual.pdf README.md
	rm manual.pdf
	make clean -C doc/

clean:
	rm -f $(NAME) ./*.tar ./*.pdf
