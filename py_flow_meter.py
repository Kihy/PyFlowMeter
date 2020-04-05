import pyshark
import sys

def flow_meter(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    for packet in cap:
        print(packet.tcp.stream)


if __name__ == '__main__':
    flow_meter(sys.argv[1])
