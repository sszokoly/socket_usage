#!/usr/bin/python
'''
#############################################################################
## Name: socket_usage.py
## Description: provides a rough estimate of the number of active sockets
## found in a pcap file, requires tshark to be available in the $PATH
## Options: see help, -h
## Version: see option -v
## Date: 2017-11-24
#############################################################################
'''
import os
import sys
from operator import itemgetter
from optparse import OptionParser
from subprocess import Popen, PIPE
try:
    from collections import Counter
except:
    from heapq import nlargest
    
    class Bag(object):
        """
        Counter Class as per https://code.activestate.com/recipes/259174/
        suggested by https://docs.python.org/2/library/collections.html
        """
        def __init__(self, iterable=()):
            self._data = {}
            self._len = 0
            self.update(iterable)
        def update(self, iterable):
            if isinstance(iterable, dict):
                for elem, n in iterable.iteritems():
                    self[elem] += n
            else:
                for elem in iterable:
                    self[elem] += 1
        def __contains__(self, elem):
            return elem in self._data
        def __getitem__(self, elem):
            return self._data.get(elem, 0)
        def __setitem__(self, elem, n):
            self._len += n - self[elem]
            self._data[elem] = n
            if n == 0:
                del self._data[elem]
        def __delitem__(self, elem):
            self._len -= self[elem]
            del self._data[elem]
        def __len__(self):
            assert self._len == sum(self._data.itervalues())
            return self._len
        def __eq__(self, other):
            if not isinstance(other, Bag):
                return False
            return self._data == other._data
        def __ne__(self, other):
            if not isinstance(other, Bag):
                return True
            return self._data != other._data
        def __hash__(self):
            raise TypeError
        def __repr__(self):
            return 'bag(%r)' % self._data
        def copy(self):
            return self.__class__(self)
        __copy__ = copy # For the copy module
        def __deepcopy__(self, memo):
            from copy import deepcopy
            result = self.__class__()
            memo[id(self)] = result
            data = result._data
            result._data = deepcopy(self._data)
            result._len = self._len
            return result
        def __getstate__(self):
            return self._data.copy(), self._len
        def __setstate__(self, data):
            self._data = data[0].copy()
            self._len = data[1]
        def clear(self):
            self._data.clear()
            self._len = 0
        def __iter__(self):
            for elem, cnt in self._data.iteritems():
                for i in xrange(cnt):
                    yield elem
        def iterunique(self):
            return self._data.iterkeys()
        def itercounts(self):
            return self._data.iteritems()
        def mostcommon(self, n=None):
            if n is None:
                return sorted(self.itercounts(), key=itemgetter(1), reverse=True)
            it = enumerate(self.itercounts())
            nl = nlargest(n, ((cnt, i, elem) for (i, (elem, cnt)) in it))
            return [(elem, cnt) for cnt, i, elem in nl]


    Counter = Bag

SYN = 0b1000
ACK = 0b0100
FIN = 0b0010
RST = 0b0001
DEBUG = 0
VERSION = 0.2
DESCRIPTION = '''
This script attempts to give the rough estimate of the number of active sockets
found in a pcap file provided as argument, requires tshark to be available in the
$PATH.
'''


class Connection():
    """
    Stores some connection related information.
    """
    def __init__(self, conn_info):
        self.client_ip = conn_info['client_ip']
        self.client_port = conn_info['client_port']
        self.server_ip = conn_info['server_ip']
        self.server_port = conn_info['server_port']
        self.client_seq = None
        self.client_ack = None
        self.server_seq = None
        self.server_ack = None
    @property
    def is_closed(self):
        if self.client_seq is not None and self.client_ack is not None and\
           self.server_seq is not None and self.server_ack is not None:
           return True
        return False
    @property
    def is_lingering(self):
        if (self.client_seq is not None or self.server_seq is not None) and\
           (self.server_ack is None or self.server_ack is None):
            return True
        return False
    @property
    def is_open(self):
        if self.client_seq is None and self.server_seq is None:
            return True
        return False
    def __str__(self):
        return ' '.join((
            'Client:', 
            ':'.join((self.client_ip.rjust(15), str(self.client_port).rjust(5))),
            'Seq:' + str(self.client_seq).rjust(10),
            'Ack:' + str(self.client_ack).rjust(10),
            '<->',
            'Server:',
            ':'.join((self.server_ip.rjust(15), str(self.server_port).rjust(5))),
            'Seq:' + str(self.server_seq).rjust(10),
            'Ack:' + str(self.server_ack).rjust(10),
            ))


def tshark_path():
    """
    Returns the path to tshark on Linux and Windows.
    :return: string
    """
    if sys.platform == 'linux2':
        tshark_file = '/usr/sbin/tshark'
        if os.path.isfile(tshark_file) and os.access(tshark_file, os.X_OK):
            return ' '.join(('nice -19', tshark_file))
        else:
            for path in os.environ['PATH'].split(os.pathsep):
                tshark_file = os.path.join(path.strip('"'), 'tshark')
                if os.path.isfile(tshark_file) and os.access(tshark_file, os.X_OK):
                    return ' '.join(('nice', tshark_file))
    elif 'win' in sys.platform:
        path_bit64 = 'c:\\Program Files\\Wireshark\\tshark.exe'
        path_bit32 = 'c:\\Program Files (x86)\\Wireshark\\tshark.exe'
        if os.path.exists(path_bit64):
            if sys.platform == 'cygwin':
                path_bit64 = '/cygdrive/c/Program Files/Wireshark/tshark.exe'
            return path_bit64
        elif os.path.exists(path_bit32):
            if sys.platform == 'cygwin':
                path_bit32 = '/cygdrive/c/Program Files (x86)/Wireshark/tshark.exe'
            return path_bit32          
        return ''
    else:
        return ''


def pcap_reader(infile, host_filter='', port_filter=''):
    """
    Parses pcap file and returns text output of each packet with certain fields
    :param one mandatory, two options strings
    :return: iterator, which yields the output of tshark line by line
    """
    R = '-R'
    tshark = tshark_path()
    if not tshark:
        print 'ERROR: Tshark not found, exiting'
        raise KeyboardInterrupt
    if sys.platform != 'linux2':
        tshark = '"' + tshark + '"'
        R = '-Y'
    default_filter = 'tcp'
    if host_filter:
        host_filter = ''.join((
            '(', 
            '||'.join('ip.addr==' + x for x in host_filter.split('|')),
            ')',
            ))
    if port_filter:
        port_filter = ''.join((
            '(',
            '||'.join('tcp.port==' + x for x in port_filter.split('|')),
            ')',
            ))
    display_filter = ''.join((
            '"',
            '&&'.join(x for x in (default_filter, host_filter, port_filter) if x),
            '"',
            ))
    fields = ' '.join((
        '-ln',
        '-E separator="|"',
        '-T fields',
        '-e frame.number',
        '-e ip.src',
        '-e tcp.srcport',
        '-e ip.dst',
        '-e tcp.dstport',
        '-e tcp.seq',
        '-e tcp.ack',
        '-e tcp.flags.syn',
        '-e tcp.flags.ack',
        '-e tcp.flags.fin',
        '-e tcp.flags.reset',
        ))
    cmd = ' '.join((tshark, R, display_filter, fields, '-r', infile))
    if DEBUG:
        print 'tshark command: %s' % [cmd]
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    return iter(proc.stdout.readline, '')


def main():
    global DEBUG
    parser = OptionParser(
        usage='%prog [<options>] <pcapfile>',
        description=DESCRIPTION)
    parser.add_option('--hosts',
        action='store',
        default='',
        dest='hosts',
        metavar=' ',
        help='host filter, if multiple separated by "|"')
    parser.add_option('--ports',
        action='store',
        default='',
        dest='ports',
        metavar=' ',
        help='port filter, if multiple separated by "|"')
    parser.add_option('-d',
        action='store_true',
        default=False,
        dest='debug',
        metavar=' ',
        help='enable debug output')
    parser.add_option('-v',
        action='store_true',
        default=False,
        dest='verbose',
        metavar=' ',
        help='verbose mode, prints open/lingering connections first')
    parser.add_option('--version',
        action='store_true',
        default=False,
        dest='version',
        metavar=' ',
        help='show version and exit')
    opts, args = parser.parse_args()
    if opts.version:
        print 'v' + str(VERSION)
        return 0
    if opts.debug:
        DEBUG = 1
    conn_info = {}
    connections = {}
    for filename in args:
        if opts.verbose:
            print 'Processing %s' % filename
        reader = pcap_reader(filename, opts.hosts, opts.ports)
        for line in reader:
            if DEBUG:
                print 'Packet: %s' % [line.strip()]
            #possibly ICMP unreachable respose
            if ',' in line:
                continue
            no, srcip, srcport, dstip, dstport, seq, ack, flags = line.split('|', 7)
            seq = int(seq)
            ack = int(ack)
            flags = int(flags.replace('|', ''), 2)
            fs = frozenset([srcip, srcport, dstip, dstport])
            if (flags & SYN and flags & ACK) or\
               (flags & ACK and not flags & RST and fs not in connections):
                if DEBUG:
                    print 'In SYNACK: %s' % [fs]
                if int(srcport) > int(dstport):
                    conn_info['client_ip'] = srcip
                    conn_info['client_port'] = int(srcport)
                    conn_info['server_ip'] = dstip
                    conn_info['server_port'] = int(dstport)
                else:
                    conn_info['client_ip'] = dstip
                    conn_info['client_port'] = int(dstport)
                    conn_info['server_ip'] = srcip
                    conn_info['server_port'] = int(srcport)
                if DEBUG:
                    print 'conn_info: %s' % [conn_info]
                connections.update({ fs : Connection(conn_info)})
            elif flags & FIN and fs in connections:
                if DEBUG:
                    print 'In FIN: %s' % [fs]
                if srcip == connections[fs].client_ip:
                    connections[fs].client_seq = seq
                    if flags & ACK and\
                       connections[fs].server_seq is not None and\
                       ack > connections[fs].server_seq:
                        connections[fs].client_ack = ack
                elif srcip == connections[fs].server_ip:
                    connections[fs].server_seq = int(seq)
                    if flags & ACK and\
                       connections[fs].client_seq is not None and\
                       ack > connections[fs].client_seq:
                        connections[fs].server_ack = ack
            elif flags == ACK and fs in connections:
                if DEBUG:
                    print 'In ACK: %s' % [fs]
                if srcip == connections[fs].client_ip:
                    if connections[fs].server_seq and not\
                       connections[fs].client_ack and\
                       ack > connections[fs].server_seq:
                        connections[fs].client_ack = ack
                elif srcip == connections[fs].server_ip:
                    if connections[fs].client_seq and not\
                       connections[fs].server_ack and\
                       ack > connections[fs].client_seq:
                        connections[fs].server_ack = ack
            elif (flags & RST) and fs in connections:
                if DEBUG:
                    print 'In RST %s' % [fs]
                if srcip == connections[fs].client_ip:
                    connections[fs].client_ack = 0
                    if connections[fs].client_seq is None:
                        connections[fs].client_seq = int(seq)-1
                elif srcip == connections[fs].server_ip:
                    connections[fs].server_ack = 0
                    if connections[fs].server_seq is None:
                        connections[fs].server_seq = int(seq)-1
        if opts.verbose:
            for value in (x for x in connections.values() if not x.is_closed):
                print value
    s = Counter((x.server_ip for x in connections.values()))
    c = Counter((x.client_ip for x in connections.values()))
    if len(connections):
        title = ' '.join((
            'Server'.center(15),
            'Total'.rjust(6),
            'Open'.rjust(6),
            'Linger'.rjust(6),
            'Client'.center(16),
            'Total'.rjust(6),
            'Open'.rjust(6),
            'Linger'.rjust(6),
            ))
        sep = len(title) * '-'
        print sep
        print title
        print sep
        for srv,clt in zip(sorted(s.iteritems(), key=itemgetter(1), reverse=True),
                           sorted(c.iteritems(), key=itemgetter(1), reverse=True)):
            srv_conn = [x for x in connections.values() if x.server_ip == srv[0]]
            srv_estab = [x for x in srv_conn if x.is_open]
            srv_ling = [x for x in srv_conn if x.is_lingering]
            clt_conn = [x for x in connections.values() if x.client_ip == clt[0]]
            clt_estab = [x for x in clt_conn if x.is_open]
            clt_ling = [x for x in clt_conn if x.is_lingering]
            summary = ' '.join((
                srv[0].rjust(15),
                str(len(srv_conn)).rjust(6), 
                str(len(srv_estab)).rjust(6), 
                str(len(srv_ling)).rjust(6),
                clt[0].rjust(16),
                str(len(clt_conn)).rjust(6), 
                str(len(clt_estab)).rjust(6), 
                str(len(clt_ling)).rjust(6),
                ))
            print summary
    if len(c) != len(s):
        print '...truncated by zip...'
    total_open = len([x for x in connections.values() if x.is_open])
    total_linger = len([x for x in connections.values() if x.is_lingering])
    print '\nTotal no. of open sockets: %d' % total_open
    print 'Total no. of ligering sockets: %d' % total_linger


if __name__ == '__main__':
    sys.exit(main())
