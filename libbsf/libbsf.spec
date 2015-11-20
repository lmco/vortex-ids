Summary: BSF--A stream filtering mechanism
Name: libbsf
Version: 1.0.1
Release: 4.LM
License: GPLv2
Group: System Environment/Libraries
Url: http://vortex-ids.sourceforge.net/
Source0: bsf.h
Source1: libbsf.c
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: libpcap
BuildRequires: libpcap, libpcap-devel


%description
BSF is a stream filtering mechanism based on BPF.

%prep
cp -fp %{SOURCE0} ./
cp -fp %{SOURCE1} ./ 


%build
#gcc %optflags libbsf.c -o libbsf.o
#gcc %optflags -static libbsf.o -o libbsf.a -lpcap
gcc %optflags -fPIC -shared -Wl,-soname,libbsf.so.%{version} libbsf.c -o libbsf.so.%{version}



%install
%{__rm} -rf %{buildroot}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}
mkdir -p $RPM_BUILD_ROOT/%{_includedir}
#install -m 644 -p $RPM_BUILD_DIR/libbsf.a $RPM_BUILD_ROOT%{_libdir}/libbsf.a
install -m 644 -p $RPM_BUILD_DIR/libbsf.so.%{version} $RPM_BUILD_ROOT%{_libdir}/libbsf.so.%{version}
ln -s %{_libdir}/libbsf.so.%{version} $RPM_BUILD_ROOT%{_libdir}/libbsf.so
install -m 644 -p $RPM_SOURCE_DIR/bsf.h $RPM_BUILD_ROOT%{_includedir}/bsf.h


%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0744)
#%{_libdir}/libbsf.a
%{_libdir}/libbsf.so
%{_libdir}/libbsf.so.%{version}
%{_includedir}/bsf.h

%changelog

* Fri Jul 3 2009 Charles Smutz <opensource.tools.security@lmco.com> - 1.0.1-4
- Rebuilt
* Fri Mar 23 2009 Charles Smutz <opensource.tools.security@lmco.com> - 1.0.1-3
- Package for release as open source
* Fri Jan 01 2009 Charles Smutz <opensource.tools.security@lmco.com> - 1.0.0-1
- Initial Package
