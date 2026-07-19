Name:           atomdns
Version:        0.74
Release:        1.0
Summary:        DNS server that chains handlers
License:        ASL-2.0
URL:            https://atomdns.miek.nl
Source0:        %{name}-%{version}.tar.gz
Source1:        atomdns.service
BuildRequires:  pkgconfig(systemd)
%{?systemd_ordering}

%description
DNS server that chains handlers.
https://atomdns.miek.nl

%define services atomdns.service
%define _topdir %(echo $PWD)/

%prep

%build
cd %{_topdir}/../..
CGO_ENABLED=0 go build

%install
cp %{_topdir}%{name}.service %{buildroot}/../%{name}.service
cp %{_topdir}%{name}.conf    %{buildroot}/../%{name}.conf
cp %{_topdir}/../../%{name}  %{buildroot}/../%{name}

install -D -m 0755 %{name}         %{buildroot}/%{_bindir}/%{name}
install -D -m 0640 %{name}.conf    %{buildroot}/usr/lib/sysusers.d/%{name}.conf
install -D -m 0644 %{name}.service %{buildroot}/%{_unitdir}/%{name}.service

%files
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
/usr/lib/sysusers.d/%{name}.conf

%post
%systemd_post atomdns.service
mkdir /var/lib/atomdns && chown atomdns:atomdns /var/lib/atomdns

%preun
%systemd_preun atomdns.service

%postun
%systemd_postun_with_restart atomdns.service
