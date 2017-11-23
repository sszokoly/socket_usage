# socket_usage
Provides a rough estimate of the total number of active tcp connections extracted from a pcap file
provided as argument. It assumes the higher port numbers are the client side ephemeral ports and the
lower ports are the services ports. Also it assumes whe RST is sent or received the socket is freed.
It also does not care about the net.ipv4.tcp_fin_timeout parameter. It simply assumes the socket is closed
when the 4-way-handshake is completed.

```
$ python socket_usage.py 1700_1710.pcap.pcapng

Server IP         Qty     Client IP         Qty
-----------------------------------------------
10.1.1.1          186      10.1.1.1          39
10.20.176.204      69      10.220.180.109    31
10.33.227.105      10       10.20.176.204     5
10.23.182.156      10        10.79.46.246     5
10.23.182.131      10       10.29.196.174     4
10.17.157.119       5        10.29.196.62     3
10.23.144.102       4         10.5.34.121     3
  10.9.45.168       3        10.29.193.16     3
  10.21.197.8       1      10.246.166.194     3
  10.8.224.83       1      10.239.198.174     2
...truncated...

Total no. of active sockets: 299

```