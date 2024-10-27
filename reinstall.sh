# !#/bin/bash

systemctl stop ft_shield
rm -rf /etc/systemd/system/ft_shield.service
rm -rf /etc/init.d/ft_shield
rm -rf /usr/local/bin/ft_shield 
make
./ft_shield