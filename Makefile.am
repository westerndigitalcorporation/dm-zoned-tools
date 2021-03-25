# SPDX-License-Identifier: CC0-1.0
#
# Copyright (C) 2020 Western Digital Corporation or its affiliates.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . $(subdirs)
EXTRA_DIST = autogen.sh

pkgconfdir = $(libdir)/pkgconfig

pkgconf_DATA = dmzadm.pc
sbin_PROGRAMS =

dist_man8_MANS =

include src/Makemodule.am
include man/Makemodule.am

if BUILD_RPM

rpmdir = $(abs_top_builddir)/rpmbuild

EXTRA_DIST += dm-zoned-tools.spec
RPMARCH=`$(RPM) --eval %_target_cpu`

spec: dm-zoned-tools.spec.in
	@echo "Generating rpm spec file..."
	@echo "Version:        $(PACKAGE_VERSION)" > dm-zoned-tools.spec
	@cat dm-zoned-tools.spec.in | grep -v '# ' >> dm-zoned-tools.spec

rpm: spec dist
	@echo "Building RPM package..."
	@mkdir -p $(rpmdir)
	$(RPMBUILD) -ta --clean -D "_topdir $(rpmdir)" dm-zoned-tools-$(PACKAGE_VERSION).tar.gz
	@mv -f $(rpmdir)/RPMS/$(RPMARCH)/*.rpm $(abs_top_builddir)
	@mv -f $(rpmdir)/SRPMS/*.rpm $(abs_top_builddir)
	@rm -rf $(rpmdir)
	@rm -f dm-zoned-tools-$(PACKAGE_VERSION).tar.gz
	@rm -f dm-zoned-tools.spec
else
rpm:
	@echo "Building RPM packages requires rpmbuild and rpm utilities"
	exit 1
endif

