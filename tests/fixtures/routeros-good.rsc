# Fixture: MikroTik RouterOS yang SUDAH baik
/system identity
set name=MTK-BAIK

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set ssh disabled=no
set www-ssl disabled=no

/snmp community
add name=Str4wB3rryR4nd0m
add name=MonitorK3ras

/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop in-interface=ether1
add chain=forward action=drop connection-state=invalid

/tool mac-server
set allowed-interface-list=none

/tool bandwidth-server
set enabled=no

/ip neighbor discovery-settings
set discover-interface-list=none

/system ntp client
set enabled=yes

/system logging
add action=remote remote=10.10.0.5 remote-port=514
