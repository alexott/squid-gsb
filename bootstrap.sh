#! /bin/sh

set -x
# aclocal -I config
aclocal
#libtoolize --force --copy
#gettextize -c -f
autoheader
automake --add-missing --copy
autoconf
