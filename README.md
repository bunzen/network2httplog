# network2httplog
pcap to proxy-like log

dependency: scapy

 $ pip install Scapy

    Usage: network2httplog.py [options]

    Options:
      -h, --help            show this help message and exit
      -o FILE, --output=FILE
                            write output to FILE
      -r INPUT, --read=INPUT
                            Read from pcap FILE
      -i INTERFACE, --interface=INTERFACE
                            Listen interface
      -f LIST, --filter=LIST
                            LIST of ports to listen on. Default: 80,3128,8080
      -F, --forceflush      Force output flush after each log entry.
      -R, --referer         Include referer in log output

