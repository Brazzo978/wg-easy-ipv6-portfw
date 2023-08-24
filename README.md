# wg-easy-ipv6-portfw

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest. For most VPS providers, you can just enter through all the questions.

```bash
wget https://raw.githubusercontent.com/Brazzo978/wg-easy-ipv6-portfw/main/wg-setup.sh
bash ./wg-setup.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.
