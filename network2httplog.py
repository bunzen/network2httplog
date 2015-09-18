#!/usr/bin/env python
"""
Copyright (c) 2013, Geir Skjotskift <geir@underworld.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

from scapy.all import sniff
from sys import stdout
from datetime import datetime
from optparse import OptionParser

DEFAULT_PORTS = [80, 8080, 3128]

FILTER_TEMPLATE = 'tcp and (port {0})'

LOG_HEADER = '#Client [timestamp] Host "Method URI" Type Size\n'
LOG_LINE = '{client} [{timestamp}] {host} "{method} {uri}" {type} {size}\n'

METHODS = ['GET', 'POST', 'CONNECT', 'PUT']

def get_filter(ports):
    """Creates a string used as filter in sniffer mode

    Arguments:

    ports - Integer list of ports to listen on"""

    return FILTER_TEMPLATE.format(' or port '.join(str(c) for c in ports))


def generate_logger_function(output=stdout, header=True, referer=False, forceflush=False):
    """Logger function to pass into sniffer or use with the
    pcap reader

    Arguments:

    output - File or IO to write log to (must provide the .write() method
    header - Boolean. Wether or not a header should be provided on create.
             Default is True"""

    def logger(packet):
        parsed_header = parse_http_header(packet)
        if parsed_header:
            output.write(LOG_LINE.format(**parsed_header))
            if forceflush:
                output.flush()

    if referer:
        global LOG_HEADER, LOG_LINE
        LOG_HEADER = LOG_HEADER.strip() + " \"Referrer\"\n"
        LOG_LINE = LOG_LINE.strip() + " \"{referer}\"\n"

    if not hasattr(output, 'write'):
        raise InvalidOutput()

    if header:
        output.write(LOG_HEADER)
    return logger


def contains_header(packet):
    """Check if the provided packet contains a HTTP header

    Arguments:

    packet - a scapy packet"""

    if packet.haslayer("TCP") and packet["TCP"].haslayer("Raw"):
        payload = packet["TCP"]["Raw"].fields["load"]
        for method in METHODS:
            if payload.startswith(method):
                return True
    return False


def parse_http_header(packet):
    """Parse out log fields from a packet return a
    dictionary for use with the logger.

    Arguments:

    packet - a scapy packet"""

    if not contains_header(packet):
        return False
    lines = str(packet["TCP"].payload).split('\n')
    packet_data = {'method': 'UNKNOWN',
                   'referer': '',
                   'host': packet["IP"].dst}

    method_line = lines[0]
    for method in METHODS:
        if method_line.find(method, 0, len(method)) >= 0:
            packet_data['method'] = method
            rest = method_line[len(method):].strip().split()
            try:
                packet_data['uri'] = rest[0]
            except IndexError:
                packet_data['uri'] = 'UNKNOWN'
            try:
                packet_data['type'] = rest[1]
            except IndexError:
                packet_data['type'] = 'UNKNOWN'
            break

    for line in lines[1:]:
        if line.lower().startswith("host"):
            packet_data['host'] = line[6:].strip()
        if line.lower().startswith("referer") or line.lower().startswith("referrer"):
            packet_data['referer'] = " ".join(line.split(" ")[1:]).strip()

    packet_data['size'] = '-'
    packet_data['client'] = packet["IP"].src
    packet_data['timestamp'] = datetime.fromtimestamp(packet.time).isoformat()

    return packet_data

def main():

    parser = OptionParser()
    parser.add_option("-o", "--output", dest="output",
                      help="write output to FILE", metavar="FILE",
                      default=None)
    parser.add_option("-r", "--read", dest="input",
                      default=None, help="Read from pcap FILE")
    parser.add_option("-i", "--interface", dest="interface",
                      default=None, help="Listen interface")
    parser.add_option("-f", "--filter", dest="filter", default=None,
                      metavar="LIST",
                      help="LIST of ports to listen on. Default: 80,3128,8080")
    parser.add_option("-F", "--forceflush", dest="forceflush",
                      default=False, action="store_true",
                      help="Force output flush after each log entry.")
    parser.add_option("-R", "--referer", dest="referer", default=False,
                      action="store_true",
                      help="Include referer in log output")

    (options, _) = parser.parse_args()

    if options.output:
        logger = generate_logger_function(open(options.output, 'wb'),
                                          referer = options.referer,
                                          forceflush=options.forceflush)
    else:
        logger = generate_logger_function(referer = options.referer,
                                          forceflush=options.forceflush)

    if options.filter:
        packet_filter = get_filter(int(n) for n in options.filter.split(','))
    else:
        packet_filter = get_filter(DEFAULT_PORTS)


    sniff(iface=options.interface, filter=packet_filter, store=0, offline=options.input, prn=logger)

class InvalidOutput(Exception):

    def __init__(self):

        Exception.__init__(self, "Invalid output object, must provide .write() method")

if __name__ == '__main__':
    main()
