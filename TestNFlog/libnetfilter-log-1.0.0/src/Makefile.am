# This is _NOT_ the library release version, it's an API version.
# Extracted from Chapter 6 "Library interface versions" of the libtool docs.
#
# <snippet>
# Here are a set of rules to help you update your library version information:
#
# 1. Start with version information of `0:0:0' for each libtool library.
# 2. Update the version information only immediately before a public release
# of your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
# 3. If the library source code has changed at all since the last update,
# then increment revision (`c:r:a' becomes `c:r+1:a').
# 4. If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0.
# 5. If any interfaces have been added since the last public release, then
# increment age.
# 6. If any interfaces have been removed since the last public release, then
# set age to 0.
# </snippet>
#
LIBVERSION=2:0:1

INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS = -fPIC -Wall
LIBS = @LIBNFLOG_LIBS@

lib_LTLIBRARIES = libnetfilter_log.la libnetfilter_log_libipulog.la

libnetfilter_log_la_LDFLAGS = -Wc,-nostartfiles -lnfnetlink	\
			      -version-info $(LIBVERSION)
libnetfilter_log_la_SOURCES = libnetfilter_log.c 

libnetfilter_log_libipulog_la_LDFLAGS = -Wc,-nostartfiles	\
					-version-info 1:0:0
libnetfilter_log_libipulog_la_LIBADD = libnetfilter_log.la
libnetfilter_log_libipulog_la_SOURCES = libipulog_compat.c
