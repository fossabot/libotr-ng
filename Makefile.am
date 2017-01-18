# SOURCES =
#include src/include.am

SUBDIRS = src src/test

#Compilation and linkage flags
#CFLAGS = -std=c99 -g -Wall `pkg-config --cflags glib-2.0`
#LDLIBS = `pkg-config --libs glib-2.0`
#CC = gcc

test: check
	$(top_builddir)/src/test/test

ci: test mem-check

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

mem-check: all
	valgrind --quiet --leak-check=full $(top_builddir)/src/test/test
