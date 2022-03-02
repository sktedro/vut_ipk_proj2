NAME=doc

ALLFILES=$(NAME).tex Makefile

all: pdf

pdf:
	pdflatex $(NAME).tex
	bibtex $(NAME).aux
	pdflatex $(NAME).tex
	pdflatex $(NAME).tex

clean:
	rm -f *.log *.dvi *.pdf *.aux *.out *.bbl *.blg *.toc
