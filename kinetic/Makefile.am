include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

plugindir = @plugindir@

kinetic_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)

kinetic_la_CFLAGS = $(PLUGIN_CFLAGS)

plugin_LTLIBRARIES = kinetic.la
kinetic_la_SOURCES = packet-kinetic.c moduleinfo.h 
kinetic_la_LDFLAGS = -module -avoid-version -shared -Wl,-soname,kinetic.so -o kinetic.so
kinetic_la_LIBADD = @PLUGIN_LIBS@ 

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS = wireshark-glue-kinetic.o  kinetic.pb.o -lprotobuf

CLEANFILES = \
	kinetic \
	*~

EXTRA_DIST = \
   Makefile.nmake
