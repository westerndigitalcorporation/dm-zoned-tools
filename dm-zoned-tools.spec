Name:		dm-zoned-tools
Version:	2.2.1
Release:	1%{?dist}
Summary:	Provides utilities to format, check and repair Linux dm-zoned devices

License:	GPLv3+
URL:		https://github.com/westerndigitalcorporation/%{name}
Source0:	%{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:	pkgconfig(devmapper)
BuildRequires:	pkgconfig(libkmod)
BuildRequires:	pkgconfig(uuid)
BuildRequires:	pkgconfig(blkid)
BuildRequires:	pkgconfig(libudev)
BuildRequires:	autoconf
BuildRequires:	autoconf-archive
BuildRequires:	automake
BuildRequires:	libtool
BuildRequires:	make
BuildRequires:	gcc

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
%make_install

%files
%{_sbindir}/dmzadm
%{_mandir}/man8/dmzadm.*

%license COPYING.GPL
%doc README.md CONTRIBUTING

%changelog
* Tue Dec 21 2021 Damien Le Moal <damien.lemoal@wdc.com> 2.2.1-1
- Version 2.2.1 package
* Wed Sep 01 2021 Damien Le Moal <damien.lemoal@wdc.com> 2.2.0-1
- Add "systemd-devel" as a build dependency
- Version 2.2.0 package
* Thu Jul 01 2021 Damien Le Moal <damien.lemoal@wdc.com> 2.1.3-1
- Add "make" as a build dependency 
- Version 2.1.3 package
* Mon Jun 14 2021 Damien Le Moal <damien.lemoal@wdc.com> 2.1.2-1
- Version 2.1.2 initial package
