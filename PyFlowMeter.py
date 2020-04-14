import argparse
import sys
from itertools import product
from Interfaces import *
import numpy as np
import pyshark
import os
from IncrementalStatistics import IncStats


def decode_flags(flag):
    """
    decodes the flag field into a integer array of flag counts.

    Args:
        flag (hexadecimal): the flag field in TCP packet.

    Returns:
        integer array: array of length 8 indicating corresponding flags.

    """
    str_rep = "{:08b}".format(eval(flag))
    return np.array([i for i in str_rep], dtype='int32')


def cartesian_product(*args, seperator="_"):
    """
    creates fieldname as product of args, joined by _.
    e.g. args=["a","b"],["c","d"] will return ["a_c","a_d","b_c","b_d"]

    Args:
        *args (args): iterables to be joined.

    Returns:
        list: list of strings.

    """
    return_list = []
    for field in product(*args):
        return_list.append(seperator.join(field))
    return return_list


def tcp_extractor(packet):
    """
    extracts information from a single tcp packet

    Args:
        packet (packet.tcp): only the tcp packet, all other layers are decapsulated.

    Returns:
        dictionary: information required for flow extraction.

    """
    packet_info = {
        "protocol": "TCP",
        "dst_port": packet.dstport,
        "src_port": packet.srcport,
        "flags": packet.flags,
        "len": packet.len,
        "time_delta": packet.time_delta,
        "duration": packet.time_relative
    }
    return packet_info


class OfflinePacketStreamingInterface(StreamingInterface):
    """
    The offline packet streaming interface that reads pcap files and notifies
    the observers about each packet.

    Args:
        pcap_file_path (string): path to pcap file.

    Attributes:
        _observers (set): set of observers.

    """

    def __init__(self, pcap_file_path):
        self._observers = set()
        self.pcap_file_path = pcap_file_path

    def attach(self, observer):
        observer._subject = self
        self._observers.add(observer)

    def detach(self, observer):
        observer._subject = None
        self._observers.discard(observer)

    def _notify(self, packet):
        for observer in self._observers:
            observer.update(packet)

    def start(self):
        """
        starts reading capture file, notifies observers of each packet,
        signals end when done

        Returns:
            None:

        """
        cap = pyshark.FileCapture(self.pcap_file_path)
        for packet in cap:
            self._notify(packet)
        self._end_signal()

    def _end_signal(self):
        """
        signals the end of file to observers

        Returns:
            None:

        """
        for observer in self._observers:
            observer.close()


class FlowMeter(Observer):
    """
    the flow meter which extracts various features from flow.

    Args:
        output_path (string): path to output file.

    Attributes:
        output_file (file): the output file that can be used write directly.
        flows (dict): a dictionary of current flows.
        timeout (int): duration to consider flow as being finished.
        feature_names (string list): list of feature names.

    """
    def __init__(self, output_path):
        self.output_file = open(output_path, "w")
        self.flows = {}
        self.timeout = 600
        directions = ["fwd", "bwd"]
        ports = ["src", "dst"]
        type = ["pkt", "byte"]
        dist_features = ["mean", "std", "skewness", "kurtosis", "min", "max"]
        flags = ["FIN", "SYN", "RST", "PUSH", "ACK", "URG", "CWE", "ECE"]
        # quickly create field names by using cartesian product of strings
        self.feature_names = ["duration", "protocol"] + \
            cartesian_product(ports, ["port"]) + cartesian_product(directions, ["tot"], type) + \
            cartesian_product(directions, ["pkt_size"], dist_features) + cartesian_product(directions, ["iat"], dist_features) + \
            cartesian_product(directions, flags, ["cnt"])
        self.output_file.write(",".join(self.feature_names))
        self.output_file.write("\n")

    def update(self, packet):
        arrival_time = float(packet.sniff_timestamp)
        if packet.highest_layer == "TCP":
            # print(dir(packet.tcp))
            stream_id = packet.tcp.stream
            info = tcp_extractor(packet.tcp)
            if stream_id not in self.flows.keys():
                self._init_stream(stream_id, info, arrival_time)
            self._update_stream(info, stream_id, arrival_time)
            self._check_timeout(arrival_time)

    def _check_timeout(self, arrival_time):
        timed_out_stream = []
        for stream in self.flows.keys():
            if arrival_time - self.flows[stream]["last_time"] > self.timeout:
                timed_out_stream.append(stream)
        self._save_batch_flow(timed_out_stream)

    def _save_batch_flow(self, timed_out_stream, delete=True):
        for index in sorted(list(timed_out_stream)):
            stream = self.flows[index]
            values = [stream[x] for x in self.feature_names[:8]]
            try:
                for i in range(4):
                    values += [x for x in stream[self.feature_names[8 +
                                                                    i * 6][:-5]].get_statistics()]
            except:
                print(self.flows[index])
                print(index)
                continue
            values += [x for x in stream["fwd_flags"]]
            values += [x for x in stream["bwd_flags"]]
            self.output_file.write(",".join(str(x) for x in values))
            self.output_file.write("\n")
            if delete:
                del self.flows[index]

    def _update_stream(self, packet_info, stream_id, arrival_time):
        """
        updates the stream/connection/flow with extracted packet_info

        Args:
            packet_info (dictionary): information extracted with tcp_extractor(packet).
            stream_id (int): index of stream stored.

        Returns:
            None: The information is updated directly in stream.

        """
        stream = self.flows[stream_id]

        # determine direction
        if packet_info["src_port"] == stream["src_port"]:
            # packet sent from src port, so it is in the forwarrd direction
            direction = "fwd"
        else:
            direction = "bwd"

        packet_len = int(packet_info["len"])
        time_delta = float(packet_info["time_delta"])
        stream["last_time"] = arrival_time
        stream["duration"] = packet_info["duration"]
        stream[direction + "_tot_pkt"] += 1
        stream[direction + "_tot_byte"] += packet_len
        stream[direction + "_pkt_size"].update(packet_len)
        stream[direction + "_iat"].update(time_delta)
        stream[direction + "_flags"] += decode_flags(packet_info["flags"])

    def _init_stream(self, stream_id, packet_info, arrival_time):
        """
        initializes the stream with default values
        Args:
            stream_id (int): id of stream calculated by wireshark
            packet_info (dict): information extracted from packet.
            arrival_time (float): timestamp of arrival time

        Returns:
            dict: initialized packet information

        """
        init_dict = {}
        features = ["duration", "protocol", "src_port", "dst_port"]
        for feature in features:
            init_dict[feature] = packet_info[feature]

        init_dict["last_time"] = arrival_time

        directions = ["fwd", "bwd"]
        type = ["pkt", "byte"]
        for i in cartesian_product(directions, ["tot"], type):
            init_dict[i] = 0
        for i in cartesian_product(directions, ["iat", "pkt_size"]):
            init_dict[i] = IncStats()
        for i in cartesian_product(directions, ["flags"]):
            init_dict[i] = np.zeros(8, dtype="int32")

        self.flows[stream_id] = init_dict

    def close(self):
        self._save_batch_flow(self.flows.keys())
        self.output_file.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network traffic flow generator.')
    parser.add_argument('pcap_file', type=str, help='the pcap file to be processed')
    parser.add_argument('output_file', type=str, help='output file to stored the data')
    parser.add_argument('-r', '--recursive', action="store_true", help='whether to recursively process all files in directory')

    args = parser.parse_args()
    if args.recursive:
        for dir in list(os.listdir(args.pcap_file)):
            if dir.endswith(".pcap"):
                input_file=os.path.join(args.pcap_file,dir)
                print("processing:",input_file)
                opsi = OfflinePacketStreamingInterface(input_file)
                out_file_name=dir.split(".")[0]
                out_file=os.path.join(args.pcap_file,out_file_name+'_flow.csv')
                fm = FlowMeter(out_file)
                print("output file:",out_file)
                opsi.attach(fm)
                opsi.start()
    else:
        opsi = OfflinePacketStreamingInterface(args.pcap_file)
        fm = FlowMeter(args.output_file)
        opsi.attach(fm)
        opsi.start()
