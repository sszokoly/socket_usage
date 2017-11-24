# socket_usage
This script in the first place attempts to give a rough estimate of the total number of open
tcp sockets extracted from the pcap files provided as arguments. It assumes the higher port
number is the Client side ephemeral port and the lower port is the Server side service port.
Furthermore it does not care about the net.ipv4.tcp_fin_timeout parameter. It simply considers
the socket closed when the 4-way or half-duplex closure is properly performed. If that is not
the case it considers the socket 'lingering'. Most of the time these sockets eventually may
be closed by the server or client but that cannot be determined for sure from the pcap trace.
It requires tshark to be available at the default installation path on Windows or Linux.
In addition one of goals behind the development of this utility was that it should be able to
do what it is meant to do on Linux servers which are not connected to the Internet, thus they
can only make use of the standard python libraries and tools they come with by default.

## Example

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
