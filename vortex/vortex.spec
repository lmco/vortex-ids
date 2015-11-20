# Determine Redhat distribution version for naming and dependency checks
%define dist    %{expand:%%(/usr/lib/rpm/redhat/dist.sh --dist)}

Name: vortex 
Version: 2.9.0
Release: 59%dist
Summary: real-time passive network capture and TCP stream reassembly
Vendor: Lockheed Martin
License: GPLv2
Group: Applications/Internet
Url: http://vortex-ids.sourceforge.net/
Source0: vortex.c
Source1: vortex.init
Source2: vortex.conf
Source3: vortex_conf_parser.init
Source4: vortex.README
Source5: xpipes.c
Source6: vortex.LICENSE
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: libnids libpcap libbsf
Requires: libnids libbsf


%description
Vortex is a program that performs real-time passive network capture and TCP stream reassembly. It is designed to be used by near real time, possibly parallel, deep protocol logging and analysis applications. Vortex uses libnids internally to do the brunt of the tcp reassembly. Vortex can also be used for offline analysis. In this case, it is similar to tcpflow or the "Follow TCP Stream" functionality of Wireshark.

%prep
cp -fp %{SOURCE0} ./
cp -fp %{SOURCE1} ./ 
cp -fp %{SOURCE2} ./
cp -fp %{SOURCE3} ./
cp -fp %{SOURCE4} ./
cp -fp %{SOURCE5} ./
cp -fp %{SOURCE6} ./

%build
gcc %optflags vortex.c -o vortex -lnids -lpthread -lbsf -DWITH_BSF
gcc %optflags xpipes.c -o xpipes -lpthread

%install
rm -rf $RPM_BUILD_ROOT

# Place binary into correct directory
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
install -m 644 -p $RPM_BUILD_DIR/vortex \
   $RPM_BUILD_ROOT%{_bindir}/vortex
install -m 644 -p $RPM_BUILD_DIR/xpipes \
   $RPM_BUILD_ROOT%{_bindir}/xpipes


# Place conf files into position
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/vortex/conf
install -m 644 -p $RPM_SOURCE_DIR/vortex.conf \
   $RPM_BUILD_ROOT%{_sysconfdir}/vortex/conf/vortex.conf

# install SYSV init stuff
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 $RPM_SOURCE_DIR/vortex.init \
        $RPM_BUILD_ROOT/etc/rc.d/init.d/vortex

install -m755 $RPM_SOURCE_DIR/vortex_conf_parser.init \
        $RPM_BUILD_ROOT/etc/rc.d/init.d/vortex_conf_parser

mkdir -p $RPM_BUILD_ROOT/usr/share/vortex
install -m755 $RPM_SOURCE_DIR/vortex.README \
        $RPM_BUILD_ROOT/usr/share/vortex/README

install -m755 $RPM_SOURCE_DIR/vortex.LICENSE \
        $RPM_BUILD_ROOT/usr/share/vortex/LICENSE

%clean
%{__rm} -rf %{buildroot}

%pre


%post
# Register the service
# /sbin/chkconfig --add vortex


%preun
# only pre-erase


%postun


%files
%defattr(0755,root,root)

%config(noreplace) %{_sysconfdir}/vortex/conf/vortex.conf
%{_sysconfdir}/rc.d/init.d/vortex
%{_sysconfdir}/rc.d/init.d/vortex_conf_parser
%{_bindir}/vortex*
%{_bindir}/xpipes
/usr/share/vortex/README
/usr/share/vortex/LICENSE

%changelog

* Fri Sep 16 2011 Charles Smutz <opensource.tools.security@lmco.com> 2.9.0-59
- Documentation updates: derivative work clarification and community contributions links
* Tue Jan 04 2011 Charles Smutz <opensource.tools.security@lmco.com> 2.9.0-58
- Minor fixes--inlcude path for limits.h
* Wed Dec 15 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.9.0-57
- Rebuild for public distribution
* Tue Dec 14 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.9.0-56
- Significant performance improvements (lower CPU use by ~300%) by making calls to realloc less frequently (-x to tune)
- Set timestamps of output files to match timestamps from pcap (-d to disable)
- Remove arbitrary limit (2 GB) on stream collection sizes, now depends on system
- Wrap 32bit pcap counters with 64bit counters
- Fix cpu locking/affinity and simplify interface
- Addition of error counters for file/IO and memory errors
* Thu Jul 23 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-55
- Added more debug statement for tcp callback and idle queue
* Thu Jul 22 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-54
- Added debug statements for connection open, close, and write
* Wed May 19 2010 William Hoyt <opensource.tools.security@lmco.com> 2.8.1-52
- set init script to send messages to /dev/null
* Wed Apr 8 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-51
- Rebuild for public distribution
* Mon Apr 6 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-50
- Rebuild against libnids 1.24
* Mon Feb 22 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-49
- Rebuild for public distribution
* Wed Feb 10 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-48
- Minor fixes to xpipes, added documentation
* Tue Feb 09 2010 Charles Smutz <opensource.tools.security@lmco.com> 2.8.1-47
- Addition of xpipes
* Mon Dec 21 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.8.0-46
- More documention, cleanup for public release
* Tue Dec 02 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.8.0-45
- Changes to defaults
- Ability to dump empty streams (-v)
- Added byte counts to stats
- Report errors and stats on exit and hints if error/stats is not otherwise enabled
* Thu Jul 30 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.7.1-44
- Minor Fixes to specfile
* Wed Jul 29 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.7.1-43
- Fix to ring buffer implementation (wasn't being used) and output filename formatting
* Fri Jul 3 2009 Samuel Wenck <opensource.tools.security@lmco.com> 2.7-42
- Release named with RH distro ID
* Fri Jul 3 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.7-41
- Addition of idle timeout
* Fri May 22 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.6-40
- Minor fixes to documentation
* Thu May 21 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.6-39
- Fixed exiting timestamp error.
* Wed May 20 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.6-38
- Refinements to extended output, BSF now optional and off by default
* Tue May 19 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.6-37
- Extended extended output, minor fixes
* Fri Apr 10 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.5-36
- Addition of extended output
* Fri Apr 10 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.4-35
- Make CPU affinity locking off by default
* Fri Apr 10 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.4-34
- Addition of CPU affinity locking
* Fri Apr 10 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.3-33
- Addition of per thread priorities
* Wed Apr 8 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.2-32
- Implementation of output queue. Various thread fixes.
* Fri Mar 23 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.1-31
- Package for release as open source
* Wed Jan 14 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.1-30
- Add explicit pthread detaches (shouldn't do anything)
* Thu Jan 08 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.1-29
- Fix unterminated filter string issue
* Thu Jan 08 2009 Charles Smutz <opensource.tools.security@lmco.com> 2.1-26
- Integration of libBSF
* Mon Dec 01 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-25
- Fixes to improved init script/conf
* Wed Nov 26 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-24
- Fixes to improved init script/conf
* Mon Nov 24 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-23
- Fixes to improved init script/conf
* Mon Nov 24 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-19
- Improved init script/conf
* Wed Nov 19 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-18
- Better accounting of connections not tracked due to polling
* Mon Nov 17 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-15
- Improved logging
* Fri Oct 13 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-10
- Fix to early dumping of data
* Fri Oct 10 2008 Charles Smutz <opensource.tools.security@lmco.com> 2.0-9
- Fixes and update of defaults to vortex
* Wed Sep 17 2008 Samuel Wenck <opensource.tools.security@lmco.com> = 2.0-6
- Changed debug_level type to int
- Added option flag for libnids TCP workaround processing
- Added ability to disable libnids TCP checksum processing
