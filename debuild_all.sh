#!/bin/sh

# Erase old packages
rm -f ../opensdg_* ../opensdg-*

# Now build for all supported architectures
debuild -i -us -uc -b -aamd64
debuild -i -us -uc -b -ai386
debuild -i -us -uc -b -aarm64
debuild -i -us -uc -b -aarmhf


