# Portmon

Portmon is a simple network traffic monitoring tool.

## Install

To install
```bash
chmod +x install.sh
./install.sh
```

To uninstall
```bash
chmod +x uninstall.sh
./uninstall.sh
```

## Usage

Config ports you need to monitor

Edit config `~/.portmon/portmon.ini`

```ini
[DEFAULT]
serve_port = 9000
monitor_ports = 443,22,8080
```

Start

```bash
service portmon start
```

Stop

```bash
service portmon stop
```

Restart

```bash
service portmon restart
```

Get network traffic of port 443

```bash
> curl localhost:9000/443
Port 443 data usage: 12134354KB = 11.57GB
```

Get network traffic of port 22

```bash
> curl localhost:9000/22
Port 22 data usage: 97282KB = 0.09GB
```

## License

MIT