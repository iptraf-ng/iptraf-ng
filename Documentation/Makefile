#
# Makefile for Documentation
#

all: html pdf

html: manual.sgml
	docbook2html manual.sgml

pdf: manual.sgml
	docbook2pdf manual.sgml

manual.sgml: manual.template version
	cat manual.template | sed -e s/@@version@@/`cat version`/ \
	-e s/@@major@@/`awk -F '.' -f version.awk  < version`/ \
	> manual.sgml

clean:
	rm -f *~ *.html manual.sgml manual.pdf


