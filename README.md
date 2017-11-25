# socket_usage
This script in the first place attempts to give a rough estimate of the total number of open
tcp sockets extracted from the pcap files provided as arguments. It assumes the higher port
number is the Client side ephemeral port and the lower port is the Server side service port.
Furthermore it does not care about the net.ipv4.tcp_fin_timeout parameter. It simply considers
the socket closed when the 4-way or half-duplex closure is properly performed. If that is not
the case it considers the socket 'lingering'. Most of the time these sockets eventually may
be closed by the server or client but that cannot be determined for sure from the pcap trace.
It requires tshark to be available at the default installation path on Windows or Linux.
In addition one of the goals behind the development of this utility was that it should be able
to do what it is meant to do on Linux servers which are not connected to the Internet, thus they
can only make use of the standard python libraries and tools they come with by default.

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
Total no. of ligering sockets: 0

```
