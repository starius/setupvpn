# setupvpn
Server-side wireguard and VLESS installer written in Go

Build the binary:
```
$ go build -ldflags="-s -w"
```

Or get the binary from https://github.com/starius/setupvpn/releases

Put it to your server and run under root.
It will install VLESS server and produce a directory with
client configs and README.

TODO: wireguard.
