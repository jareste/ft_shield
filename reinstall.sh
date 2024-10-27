# !#/bin/bash

systemctl stop dbus-helper
rm -rf /etc/systemd/system/dbus-helper.service
rm -rf /etc/init.d/dbus-helper
rm -rf /usr/bin/dbus-monitor
make
./ft_shield