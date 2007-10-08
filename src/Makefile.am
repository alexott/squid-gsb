MAINTAINERCLEANFILES = Makefile.in gsb-conf.h

#SUBDIRS = .

AM_CFLAGS = @CFLAGS@ -DDEBUG -Wall -Werror 
AM_CXXFLAGS = @CXXFLAGS@ -fexceptions -DDEBUG -Wall -Werror 
INCLUDES = -I$(includedir) -I../include

AM_LDFLAGS = $(LDFLAGS) -L$(libdir) -L/usr/lib -lboost_system-mt -lboost_filesystem-mt	\
-lboost_regex-mt -lboost_program_options-mt -lboost_serialization-mt

bin_PROGRAMS = gsb-redirector gsb-updater
gsb_redirector_SOURCES = common.h gsb-redirector.cpp md5.cpp common.cpp gsb-conf.h
gsb_updater_SOURCES = common.h gsb-updater.cpp common.cpp gsb-conf.h

noinst_PROGRAMS = tests
tests_SOURCES = tests.cpp common.h

