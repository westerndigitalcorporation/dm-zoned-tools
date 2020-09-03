# SPDX-License-Identifier: CC0-1.0
#
# Copyright (C) 2020 Western Digital Corporation or its affiliates.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . $(subdirs)
EXTRA_DIST = autogen.sh

pkgconfdir = $(libdir)/pkgconfig
rpmdir = $(abs_top_builddir)/rpmbuild

pkgconf_DATA = dmzadm.pc
sbin_PROGRAMS =

dist_man8_MANS =

include src/Makemodule.am
include man/Makemodule.am

rpm: dist
	@mkdir -p $(rpmdir)/BUILD
	@mkdir -p $(rpmdir)/RPMS
	@mkdir -p $(rpmdir)/SOURCES
	@mkdir -p $(rpmdir)/SPECS
	@mkdir -p $(rpmdir)/SRPMS
	@mv dmzadm-$(PACKAGE_VERSION).tar.gz $(rpmdir)/SOURCES/
	@echo "Version:        $(PACKAGE_VERSION)" > $(rpmdir)/SPECS/dmzadm.spec
	@cat $(rpmdir)/dmzadm.spec.in >> $(rpmdir)/SPECS/dmzadm.spec
	@rpmbuild -bs -v \
		--target="$(build_cpu)" \
		-D "_topdir $(rpmdir)" \
		--nodebuginfo "$(rpmdir)/SPECS/dmzadm.spec"
	@mv -f $(rpmdir)/SRPMS/*.rpm $(abs_top_builddir)
	@rpmbuild -bb -v \
		--target="$(build_cpu)" \
		-D "_topdir $(rpmdir)" \
		--nodebuginfo "$(rpmdir)/SPECS/dmzadm.spec"
	@mv -f $(rpmdir)/RPMS/$(build_cpu)/*.rpm $(abs_top_builddir)
	@rm -rf $(rpmdir)/SRPMS
	@rm -rf $(rpmdir)/SPECS
	@rm -rf $(rpmdir)/SOURCES
	@rm -rf $(rpmdir)/RPMS
	@rm -rf $(rpmdir)/BUILDROOT
	@rm -rf $(rpmdir)/BUILD

