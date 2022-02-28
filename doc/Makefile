NAME=doc

ALLFILES=$(NAME).tex Makefile

all: pdf

pdf:
	latex $(NAME).tex
	latex $(NAME).tex
	pdflatex $(NAME).tex

dvi: 
	latex $(NAME).tex

clean:
	rm -f *.log *.dvi *.pdf *.aux *.out
