# ft_shield

`ft_shield` is a trojan service that installs itself as a Linux daemon, runs as root, and manages client connections on port 4242. It writes its own service script and configures itself to be managed by `systemctl`. The daemon listens on port 4242, logs received data, and supports up to 3 simultaneous connections. On top of it, it has the option to serve a root shell on the target device for the client connected.

## Features
- Installs as a Linux daemon.
- Manages connections on port 4242.
- Logs received messages.
- Limits to 3 simultaneous connections.
- Uses a .lock file for execution control.
- Provides root shell.

## Installation
```bash
make
sudo make install
```

## Usage
Start the service:
```bash
sudo systemctl start ft_shield
```

Check status:
```bash
sudo systemctl status ft_shield
```

Stop the service:
```bash
sudo systemctl stop ft_shield
```
