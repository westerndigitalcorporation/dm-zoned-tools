# SPDX-License-Identifier: CC0-1.0
#
# Copyright (C) 2020 Western Digital Corporation or its affiliates.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src man
EXTRA_DIST = autogen.sh COPYING.GPL CONTRIBUTING README.md

if BUILD_RPM

rpmdir = $(abs_top_builddir)/rpmbuild

EXTRA_DIST += dm-zoned-tools.spec
RPMARCH=`$(RPM) --eval %_target_cpu`

rpm: dist
	@echo "Building RPM package..."
	@mkdir -p $(rpmdir)
	$(RPMBUILD) -ta --clean -D "_topdir $(rpmdir)" dm-zoned-tools-$(PACKAGE_VERSION).tar.gz
	@mv -f $(rpmdir)/RPMS/$(RPMARCH)/*.rpm $(abs_top_builddir)
	@mv -f $(rpmdir)/SRPMS/*.rpm $(abs_top_builddir)
	@rm -rf $(rpmdir)
	@rm -f dm-zoned-tools-$(PACKAGE_VERSION).tar.gz
else
rpm:
	@echo "Building RPM packages requires rpmbuild and rpm utilities"
	exit 1
endif

