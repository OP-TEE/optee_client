#
# spec file for package optee-client
#
# Copyright (c) 2020 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%define libname libteec1
%define libname2 libckteec0
%define libname3 libseteec0
%define libname4 libteeacl0
Name:           optee-client
Version:        3.22.1
Release:        0
Summary:        A Trusted Execution Environment client
License:        BSD-2-Clause
Group:          System/Boot
URL:            https://github.com/OP-TEE/optee_client
Source:         https://github.com/OP-TEE/optee_client/archive/%{version}.tar.gz#/optee_client-%{version}.tar.gz
BuildRequires:  cmake

%description
This component provides the TEE Client API as defined by the
GlobalPlatform TEE standard. For a general overview of OP-TEE, the
Open Platform Trusted Execution Environment, see the Notice.md file.

%package -n %{libname}
Summary:        Library implementing TEE Client API
Group:          System/Libraries

%description -n %{libname}
This component provides the TEE Client API as defined by the
GlobalPlatform TEE standard. For a general overview of OP-TEE, the
Open Platform Trusted Execution Environment, see the Notice.md file.

%package -n %{libname2}
Summary:        Library implementing the PKCS11 API
Group:          System/Libraries

%description -n %{libname2}
This component provides the PKCS11 API using the PKCS11 trusted 
application executing in OP-TEE.For a general overview of OP-TEE, the
Open Platform Trusted Execution Environment, see the Notice.md file.

%package -n %{libname3}
Summary:        Library implementing secure element control
Group:          System/Libraries

%description -n %{libname3}
This component implements secure element control.

%package -n %{libname4}
Summary:        ACL helper library
Group:          System/Libraries

%description -n %{libname4}
This component implements the ACL helper library.


%package devel
Summary:        Files for Developing with libtee
Group:          Development/Libraries/C and C++
Requires:       %{libname2} = %{version}
Requires:       %{libname} = %{version}

%description devel
This component provides the TEE Client API as defined by the GlobalPlatform
TEE standard. For a general overview of OP-TEE, please see the Notice.md file.

This package contains the libvisio development files.

%prep
%setup -q -n optee_client-%{version}

%build
%cmake -DRPMB_EMU=0
make %{?_smp_mflags} V=1

%install
%cmake_install
mkdir -p %{buildroot}/%{_sysconfdir}/modprobe.d
%{__install} -m 0644 tee-supplicant/conf/tpm_ftpm_tee.conf %{buildroot}%{_sysconfdir}/modprobe.d/tpm_ftpm_tee.conf
%{__install} -d %{buildroot}%{_unitdir}
%{__install} -m 0644 debian/tee-supplicant.service %{buildroot}%{_unitdir}

%post -n %{libname} -p /sbin/ldconfig
%postun -n %{libname} -p /sbin/ldconfig

%post -n %{libname2} -p /sbin/ldconfig
%postun -n %{libname2} -p /sbin/ldconfig

%post -n %{libname3} -p /sbin/ldconfig
%postun -n %{libname3} -p /sbin/ldconfig

%post -n %{libname4} -p /sbin/ldconfig
%postun -n %{libname4} -p /sbin/ldconfig

%postun
systemctl daemon-reload >/dev/null 2>&1 || :

%files
%license LICENSE
%doc README.md
%{_sbindir}/tee-supplicant
%{_sysconfdir}/modprobe.d/tpm_ftpm_tee.conf
%{_unitdir}/tee-supplicant.service

%files devel
%{_includedir}/*.h
%{_libdir}/libteec.so
%{_libdir}/libckteec.so
%{_libdir}/libseteec.so
%{_libdir}/libteeacl.so

%files -n %{libname}
%{_libdir}/libteec.so.*

%files -n %{libname2}
%{_libdir}/libckteec.so.*

%files -n %{libname3}
%{_libdir}/libseteec.so.*

%files -n %{libname4}
%{_libdir}/libteeacl.so.*

%changelog
