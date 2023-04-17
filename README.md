# Packet Sniffer


The packet sniffer is a command-line tool that allows you to capture network traffic and analyze it in real-time. This tool can be useful for network troubleshooting, security auditing, and network monitoring. In this documentation is the describtion of the different options available with the packet sniffer.

## Usage

The packet sniffer can be invoked with the following command:  
```
$ ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```
Where following options are combination of parameteres:

- `-i INTERFACE` or `--interface INTERFACE`: Specifies the interface to sniff. If this parameter is not specified (and any other parameters as well), or if only `-i/--interface` is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed (additional information beyond the interface list is welcome but not required).

- `-t` or `--tcp`: Displays TCP segments and is optionally complemented by `-p` functionality.

- `-u` or `--udp`: Displays UDP datagrams and is optionally complemented by `-p` functionality.

- `-p PORT`: Extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in both the source and destination part of TCP/UDP headers.

- `--icmp4`: Displays only ICMPv4 packets.

- `--icmp6`: Displays only ICMPv6 echo request/response.

- `--arp`: Displays only ARP frames.

- `--ndp`: Displays only ICMPv6 NDP packets.

- `--igmp`: Displays only IGMP packets.

- `--mld`: Displays only MLD packets.

- `-n NUMBER`: Specifies the number of packets to display, i.e., the "time" the program runs; if not specified, consider displaying only one packet, i.e., as if `-n 1`.

  All **arguments** can be in **any order**.

## Theory

Packet sniffing is the practice of gathering, collecting, and logging some or all packets that pass through a computer network, regardless of how the packet is addressed. In this way, every packet, or a defined subset of packets, may be gathered for further analysis.  
Packet sniffing is widely used for network troubleshooting.  

This sniffer is showing these kind of information:

`Source MAC address (src MAC)`: This is the MAC address of the device that sent the packet. It uniquely identifies the device on the local network.  

`Destination MAC address (dst MAC)`: This is the MAC address of the device that should receive the packet. It uniquely identifies the device on the local network.  

`Source IP address (src IP)`: This is the IP address of the device that sent the packet. It uniquely identifies the device on the network. 

`Destination IP address (dst IP)`: This is the IP address of the device that should receive the packet. It uniquely identifies the device on the network.  

`Source port (src port)`: This is the port number used by the sending application to transmit the packet. It uniquely identifies the application on the device sending the packet.  
`Destination port (dst port)`: This is the port number used by the receiving application to listen for the packet. It uniquely identifies the application on the device receiving the packet.

## Show of output
```
src MAC: 00:15:5d:bb:9d:90
dst MAC: ff:ff:ff:ff:ff:ff
frame length 86
src IP: 172.25.0.1
dst IP: 172.25.15.255
src port: 57621
dst port: 57621

0x0000  ff ff ff ff ff ff 00 15 5d bb 9d 90 08 00 45 00  ........].....E.  ........].....E.
0x0010  00 48 4f e3 00 00 80 11 82 8f ac 19 00 01 ac 19  .HO.............  .HO.............
0x0020  0f ff e1 15 e1 15 00 34 b4 83 53 70 6f 74 55 64  .......4..SpotUd  .......4..SpotUd
0x0030  70 30 b0 e0 ca 1d 64 4d 61 4b 00 01 00 04 48 95  p0....dMaK....H.  p0....dMaK....H.
0x0040  c2 03 21 5f 44 35 f8 d9 b5 67 37 89 0b 96 4b f2  ..!_D5...g7...K.  ..!_D5...g7...K.
0x0050  e4 a5 ec 57 d9 0f  ...W..
```

## Testing  

 ### TCP packets
**command :** `./ipk-sniffer -i eth0 --tcp`  
**what was tested**: TCP packet sniffing  
**why it was tested**: To ensure functionality works as should  
**how it was tested**: We activated sniffer, checked the captured TCP packet and found the same packet in Wireshark  
**what was the testing environment**: Both NixDevelop Virtual Machine and WSL2 terminal  
**what were the inputs, expected outputs, and actual outputs**: The outputs were the same as expected, as you can see on the pictures  
<p style="text-align: center;">WIRESHARK</p>  

![tcp-wire.png](/tcp-wire.png)
<p style="text-align: center;">IPK-SNIFFER</p>  

![tcp.png](/tcp.png)

### UDP packets
**command :** `./ipk-sniffer -i eth0 --udp`  
**what was tested**: UDP packet sniffing  
**why it was tested**: To ensure functionality works as should  
**how it was tested**: We activated sniffer, checked the captured UDP packet and found the same packet in Wireshark  
**what was the testing environment**: Both NixDevelop Virtual Machine and WSL2 terminal  
**what were the inputs, expected outputs, and actual outputs**: The outputs were the same as expected, as you can see on the pictures  
<p style="text-align: center;">WIRESHARK</p>  

![wireshark-udp.png](/wireshark-udp.png)
<p style="text-align: center;">IPK-SNIFFER</p>  

![udp.png](/udp.png)

### Number of packets
**command :** `./ipk-sniffer -i eth0 --udp -n 2`  
**what was tested**: sniffing **2** packets 
**why it was tested**: To ensure functionality works as should  
**how it was tested**: We activated sniffer, checked the captured TCP packet and found the same packet in Wireshark  
**what was the testing environment**: Both NixDevelop Virtual Machine and WSL2 terminal  
**what were the inputs, expected outputs, and actual outputs**: The outputs were the same as expected, as you can see on the pictures  
<p style="text-align: center;">WIRESHARK</p>  

![n=2-wire.png](/n=2-wire.png)
<p style="text-align: center;">IPK-SNIFFER</p>  

![n=2.png](/n=2.png)

### Sniffing on given port
**command :** `./ipk-sniffer -i eth0 -p 5761`  
**what was tested**: sniffing packets on port **number 5761** 
**why it was tested**: To ensure functionality works as should  
**how it was tested**: We activated sniffer, checked the captured TCP packet and found the same packet in Wireshark  
**what was the testing environment**: Both NixDevelop Virtual Machine and WSL2 terminal  
**what were the inputs, expected outputs, and actual outputs**: The outputs were the same as expected

<p style="text-align: center;">IPK-SNIFFER</p>  

![port.png](/port.png)



## Bibliography
* https://www.devdungeon.com/content/using-libpcap-c  
* https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset  
* https://www.opensourceforu.com/2011/02/capturing-packets-c-program-libpcap/  
* https://stackoverflow.com/questions/61287831/how-to-save-the-content-of-a-udp-packet-to-a-struct-and-print-it  
* https://www.paessler.com/it-explained/packet-sniffing  
* https://linuxhint.com/send_receive_udp_packets_linux_cli/  
* https://www.programcreek.com/cpp/?CodeExample=hex+dump  
* https://stackoverflow.com/questions/3060950/how-to-get-ip-address-from-sock-structure-in-c  
* https://stackoverflow.com/questions/5177879/display-the-contents-of-the-packet-in-c  
* https://www.opensourceforu.com/2011/02/capturing-packets-c-program-libpcap/  
