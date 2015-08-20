# naprox
A Python gevent based Authoritative DNS Proxy server.

## Usage

```
naproxy.py -c config_file
```

## Configuration
The configuration uses the standard _ConfigObj_ INI format:

```
# IP address to bind to
bind = 127.0.0.1
# UDP port to listen
port = 53
# Logfile path
logfile = log/naprox.log

# Nameservers section, here resides the servers to proxify
[nameservers]
    # default is the default nameserver list to query
    default = 8.8.8.8, 8.8.4.4

# Heartbeat section, how naprox checks the forementioned servers availability
[heartbeat]
    [[default]]
        # Record to ask
        record = "google.com"
        # Record type
        type = "A"
        # check interval in seconds
        interval = 60
        # number of tries that naprox will do
        # waiting for a heartbeat result on boot time
        init_retries = 5
```
