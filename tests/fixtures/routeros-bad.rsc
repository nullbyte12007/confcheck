# Fixture: MikroTik RouterOS yang BERMASALAH (untuk menguji deteksi)
/system identity
set name=MTK-BURUK

/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
set api disabled=no
set ssh disabled=no

/snmp community
add name=public

/ip firewall filter
add chain=input action=accept connection-state=established,related

/tool mac-server
set allowed-interface-list=all

/tool bandwidth-server
set enabled=yes

/ip neighbor discovery-settings
set discover-interface-list=all

/system logging
set 0 action=memory
