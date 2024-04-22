## Start ssh daemon

```bash
sudo service ssh start
```

## View logs

```bash
sudo cat /var/log/syslog
```

## Get wsl machine address

```bash
ip addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
```