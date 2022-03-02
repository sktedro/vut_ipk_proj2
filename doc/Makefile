NAME=doc

all: pdf

pdf:
	pdflatex $(NAME).tex
	bibtex $(NAME).aux
	pdflatex $(NAME).tex
	pdflatex $(NAME).tex

clean:
	rm -f *.log *.dvi *.aux *.out *.bbl *.blg *.toc

clean_all:
	rm -f *.log *.dvi *.pdf *.aux *.out *.bbl *.blg *.toc
