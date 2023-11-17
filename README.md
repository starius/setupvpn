# setupvpn
Server-side wireguard and VLESS installer written in Go

Build the binary:
```
$ CGO_ENABLED=0 go build -ldflags="-s -w"
```

Or get the binary from https://github.com/starius/setupvpn/releases

Put it to your server and run under root.
It will install wireguard and/or/ VLESS servers and produce a directory with
client configs and README.

Flags:

```
Usage of ./setupvpn:
  -encrypt
        Put client configs into encrypted zip
  -n-clients int
        Number of client configs to generate (default 50)
  -server-ip string
        Server IP address (leave empty to determine automatically)
  -skip-vless
        Skip installing VLESS
  -skip-wireguard
        Skip installing Wireguard
  -vless-domain string
        Masking domain used by VLESS server (default "www.google.com")
  -wireguard-port int
        Port for wireguard to listen in (0 = random)
```

Use `-skip-vless` and `-skip-wireguard` options to disable the corresponding
server.

Example. Install wireguard only.

```
setupvpn -skip-vless
```

Use `-encrypt` to pack and encrypt all client configs. This is safer,
because raw configs won't be stored on the server's storage.

```
setupvpn -encrypt
Encryption password for client configs:
Client configs were compressed and encrypted and written to file /tmp/setupvpn-configs-1234567890.tar.gz.enc
Copy the file to safe place and unpack using the following command:
openssl enc -d -base64 -A -aes-256-cbc -pbkdf2 -md sha256 -in setupvpn-configs-1234567890.tar.gz.enc -out - | tar -xzf-
```
