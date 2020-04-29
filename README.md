# Fuchsia traceroute

An implementation of the traceroute utility in [Fuchsia OS](https://fuchsia.dev/), done as a part of the IT253 - Operating Systems course.

This implemantation currently uses ICMP for traceroute probes.
## Setup 
The following setup is to test this implementation in Fuchsia running on a QEMU.
- Create a tap device in the host
```
sudo ip tuntap add dev qemu mode tap user $USER && sudo ip link set qemu up
```
- Enable IP forwarding in the host
``` 
echo 1 > /proc/sys/net/ipv4/ip_forward
```
- Enable Proxy ARP for the tap device
``` 
echo 1 > /proc/sys/net/ipv4/conf/qemu/proxy_arp
```
- Assign a static IP to the tap device
```
sudo ifconfig qemu 10.0.0.101/8
```
- Assign a static IP to the default interface in the QEMU (Make sure it's in the same net as the tap device)
```
ifconfig ethp0002 add 10.0.0.100/8
```
- Add a default route in the QEMU
```
net fwd add-device 2 0.0.0.0 0
```
- Setup NAT in the host to enable access to external networks, from the QEMU
(`eth0` is the interface connected to the external network, `qemu` is the tap device)
```
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o qemu -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i qemu -o eth0 -j ACCEPT
 ```
