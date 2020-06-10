# socket_usage

This script parses pcap files and attempts to give a good estimate on TCP socket usage per host acting as Client or Server.
It assumes the host using the higher TCP port number in a connection to be the Client and the lower port side to be Server.
It does not take into account OS parameters like net.ipv4.tcp_fin_timeout. It simply considers a socket closed when the
4-way or half-duplex socket closure procedures is properly performed, otherwise the socket is marked to be in 'Linger' state.
Such lingering sockets eventually may get closed by the Server or Client side application or kernel but that cannot be
determined with certainty from a pcap trace. It requires tshark (wireshark) to be available at the default installation 
path on Windows or Linux and accessibly by the user running the script. In addition one of the goals behind the development
of this utility was that it should be able to work on Linux servers which may not be connected to the Internet, thus they can
only make use of the standard Python libraries and OS tools - like tshark - they usually come with by default.

## Example

```
$ python socket_usage.py dump_sbc_eth1__16242_20170426105150
--------------------------------------------------------------------------
     Server      Total   Open Linger      Client       Total   Open Linger
--------------------------------------------------------------------------
    10.10.9.122      8      8      0      10.10.9.128      9      9      0
    10.10.9.130      7      7      0      10.10.9.122      7      7      0
    10.10.9.124      7      7      0      10.10.9.130      6      6      0
    10.10.9.128      6      6      0      10.10.9.124      6      6      0
    10.10.8.224      5      5      0      10.10.8.224      5      5      0
     10.10.8.84      4      4      0       10.10.8.84      4      4      0
    10.10.8.185      4      4      0      10.10.8.185      4      4      0
    10.10.9.171      4      4      0      10.10.8.183      4      4      0
    10.10.8.183      3      3      0      10.10.8.184      4      4      0
    10.10.8.226      3      3      0      10.10.8.226      3      3      0
    10.10.8.184      3      3      0      10.10.9.180      2      2      0
    10.10.8.189      2      2      0      10.10.8.189      2      2      0
 192.168.215.11      1      1      0      10.10.8.186      1      1      0
    10.10.9.180      1      1      0   192.168.215.11      1      1      0
    10.10.8.186      1      1      0       10.41.3.66      1      1      0
     10.41.3.62      1      1      0      10.10.9.171      1      1      0

Total no. of open sockets: 60
Total no. of lingering sockets: 0

```
