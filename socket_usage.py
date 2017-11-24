#!/usr/bin/python
'''
#############################################################################
## Name: socket_usage.py
## Description: provides a rough estimate of the number of active sockets
## found in a pcap file, requires tshark to be available in the $PATH
## Options: see help, -h
## Version: see option -v
## Date: 2017-11-23
#############################################################################
'''
import os
import re
import sys
from operator import itemgetter
from optparse import OptionParser
from subprocess import Popen, PIPE
try:
    from collections import Counter
except:
    from heapq import nlargest
    
    class Bag(object):
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
            if not isinstance(other, bag):
                return False
            return self._data == other._data
        def __ne__(self, other):
            if not isinstance(other, bag):
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
            result._data = deepcopy(self._data, memo)
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

SYNACK = 0b1010
FINACK = 0b0110
ACK = 0b0010
RST = 0b0001
RSTACK = 0b0011
DEBUG = 0
VERSION = 0.1
DESCRIPTION = '''
This script attempts to give the rough estimate of the number of active sockets
found in a pcap file provided as argument, requires tshark to be available in the
$PATH.
'''

class Connection():
    '''
    Stores some connection related information.
    '''
    def __init__(self, conn_info):
        self.client_ip = conn_info['client_ip']
        self.client_port = conn_info['client_port']
        self.server_ip = conn_info['server_ip']
        self.server_port = conn_info['server_port']
        self.client_seq = None
        self.client_ack = None
        self.server_seq = None
        self.server_ack = None
    def __str__(self):
        l = []
        l.append(':'.join((self.client_ip, str(self.client_port))))
        l.append('<->')
        l.append(':'.join((self.server_ip, str(self.server_port))))
        return ''.join(l)

def tshark_path():
    '''
    Returns the path to tshark on Linux and Windows.
    :return: string
    '''
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
    '''

    :return:
    '''
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
        '-e tcp.flags.fin',
        '-e tcp.flags.ack',
        '-e tcp.flags.reset',
        ))
    cmd = ' '.join((tshark, R, display_filter, fields, '-r', infile))
    if DEBUG:
        print 'Tshark command: %s' % [cmd]
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
        help='host filter, if multiple separate them with "|"')
    parser.add_option('--ports',
        action='store',
        default='',
        dest='ports',
        metavar=' ',
        help='port filter, if multiple separate with "|"')
    parser.add_option('-d',
        action='store_true',
        default=False,
        dest='debug',
        metavar=' ',
        help='enable debug output')
    parser.add_option('-v', '--version',
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
    reader = pcap_reader(args[0], opts.hosts, opts.ports)
    for line in reader:
        if DEBUG:
            print 'Line: %s' % [line.strip()]
        no, srcip, srcport, dstip, dstport, seq, ack, flags = line.split('|', 7)
        flags = int(flags.replace('|', ''), 2)
        fs = frozenset([srcip, srcport, dstip, dstport])
        if flags == SYNACK or (flags == ACK and fs not in connections):
            if DEBUG:
                print 'SYNACK: %s' % [line.strip()]
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
        elif flags == FINACK and fs in connections:
            if DEBUG:
                print 'FINACK: %s' % [line.strip()]
            if srcip == connections[fs].client_ip:
                connections[fs].client_seq = int(seq)
            else:
                connections[fs].server_seq = int(seq)
        elif flags == ACK and fs in connections:
            if DEBUG:
                print 'ACK: %s' % [line.strip()]
            if srcip == connections[fs].client_ip:
                if connections[fs].server_seq and not\
                   connections[fs].client_ack and\
                   int(ack) >= connections[fs].server_seq:
                    connections[fs].client_ack = int(ack)
            elif srcip == connections[fs].server_ip:
                if connections[fs].client_seq and not\
                   connections[fs].server_ack and\
                   int(ack) >= connections[fs].client_seq:
                    connections[fs].server_ack = int(ack)
            if connections[fs].client_seq is not None and\
               connections[fs].client_ack is not None and\
               connections[fs].server_seq is not None and\
               connections[fs].server_ack is not None:
                if DEBUG:
                    print 'Removing connection: %s' % connections[fs]
                connections.pop(fs, '')
        elif (flags == RST or flags == RSTACK) and fs in connections:
            if DEBUG:
                print 'RST %s' % [line.strip()]
            #if srcip == connections[fs].client_ip:
            #    connections[fs].client_seq= int(seq)
            #    connections[fs].client_ack = 0
            #elif srcip == connections[fs].server_ip:
            #    connections[fs].server_seq = int(seq)
            #    connections[fs].server_ack = 0
            #if connections[fs].client_seqis not None and\
            #   connections[fs].client_ack is not None and\
            #   connections[fs].server_seq is not None and\
            #   connections[fs].server_ack is not None:
            connections.pop(fs, '')  
    s = Counter((x.server_ip for x in connections.values()))
    c = Counter((x.client_ip for x in connections.values()))
    print '\n%s %s     %s %s' % (
        'Server IP'.ljust(15),
        'Qty'.rjust(5),
        'Client IP'.ljust(15),
        'Qty'.rjust(5)
        )
    print 47 * '-'
    for srv,cli in zip(sorted(s.iteritems(), key=itemgetter(1), reverse=True),
                        sorted(c.iteritems(), key=itemgetter(1), reverse=True)):
        print '%s %s     %s %s' % (
            srv[0].rjust(15),
            str(srv[1]).rjust(5), 
            cli[0].rjust(15), 
            str(cli[1]).rjust(5)
        )
    print '...truncated...'
    print '\nTotal no. of active sockets: %s' % len(connections)

if __name__ == '__main__':
    sys.exit(main())