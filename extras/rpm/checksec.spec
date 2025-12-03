%global debug_package %{nil}
%global _enable_debug_packages 0
Summary:    Tool to check system for binary-hardening
Name:        checksec
Version:    3.0.2
Release:    1
License:    BSD
Group:        Development/Tools
Source0:    https://github.com/slimm609/checksec/archive/refs/tags/%{version}.tar.gz
URL:        https://github.com/slimm609/checksec
BuildRequires:    golang


%description
Modern Linux distributions offer some mitigation techniques to make it
harder to exploit software vulnerabilities reliably. Mitigations such
as RELRO, NoExecute (NX), Stack Canaries, Address Space Layout
Randomization (ASLR) and Position Independent Executables (PIE) have
made reliably exploiting any vulnerabilities that do exist far more
challenging.

The checksec script is designed to test what *standard* Linux OS and
PaX <http://pax.grsecurity.net/> security features are being used.

As of version 1.3 the script also lists the status of various Linux
kernel protection mechanisms.

checksec can check binary-files and running processes for hardening
features.

%prep
%autosetup

%build
go build -buildmode=pie -ldflags="-s -w -X 'main.version=%{version}' -extldflags '-Wl,-z,relro,-z,now,-z,noexecstack'" -o %{name} .

%install
install -d $RPM_BUILD_ROOT%{_bindir}
install -d $RPM_BUILD_ROOT%{_mandir}/man1
install -p -m 0755 %{name} $RPM_BUILD_ROOT%{_bindir}/%{name}
install -p -m 0644 extras/man/%{name}.1 $RPM_BUILD_ROOT%{_mandir}/man1/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*
