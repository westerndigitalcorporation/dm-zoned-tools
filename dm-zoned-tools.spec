# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (c) 2020 Western Digital Corporation or its affiliates.
Name:		dm-zoned-tools
Version:	2.1.1
Release:	1%{?dist}
Summary:	A program to format, check and repair Linux dm-zoned devices

License:	GPLv3+
URL:		https://github.com/westerndigitalcorporation/%{name}
Source0:	https://github.com/westerndigitalcorporation/%{name}/archive/refs/tags/v%{version}.tar.gz

BuildRoot:	%{_topdir}/BUILDROOT/
BuildRequires:	device-mapper-devel,kmod-devel,libuuid-devel,libblkid-devel,autoconf,autoconf-archive,automake,libtool

%description
This package provides the dmzadm utility which can be used to format,
check and repair zoned block devices used with Linux dm-zoned device
mapper target driver.

%prep
%autosetup

%build
sh autogen.sh
%configure
%make_build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install PREFIX=%{_prefix} DESTDIR=$RPM_BUILD_ROOT
chmod -x $RPM_BUILD_ROOT%{_mandir}/man8/*.8

%ldconfig_scriptlets

%files
%{_sbindir}/dmzadm
%{_mandir}/man8/*

%license COPYING.GPL
%doc README.md CONTRIBUTING

%changelog
* Fri May 21 2021 Damien Le Moal <damien.lemoal@wdc.com> 2.1.1-1
- Version 2.1.1 initial package
