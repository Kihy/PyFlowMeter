import binascii
import sys
from itertools import product

import numpy as np
import pyshark

from IncrementalStatistics import IncStats


def decode_flags(flag):
    str_rep = "{:08b}".format(eval(flag))
    return np.array([i for i in str_rep], dtype='int32')


def tcp_extractor(packet):
    packet_info = {
        "protocol": "TCP",
        "dst_port": packet.dstport,
        "src_port": packet.srcport,
        "flags": packet.flags,
        "len": packet.len,
        "time_delta": packet.time_delta,
        "time_relative": packet.time_relative
    }
    return packet_info


def update_stream(packet_info, stream):

    # determine direction
    if packet_info["src_port"] == stream["src_port"]:
        # packet sent from src port, so it is in the forwarrd direction
        direction = "fwd"

    else:
        direction = "bwd"
    packet_len = int(packet_info["len"])
    time_delta = float(packet_info["time_delta"])
    stream["duration"] = packet_info["time_relative"]
    stream[direction + "_tot_pkt"] += 1
    stream[direction + "_tot_byte"] += packet_len
    stream[direction + "_pkt_size"].update(packet_len)
    stream[direction + "_iat"].update(time_delta)
    stream[direction + "_flags"] += decode_flags(packet_info["flags"])



def init_stream(packet_info):
    """
    initializes the stream with default values
    Args:
        packet_info (dict): information extracted from packet.

    Returns:
        dict: initialized packet information

    """
    init_dict = {}
    directions = ["fwd", "bwd"]
    type = ["pkt", "byte"]
    init_dict["duration"] = packet_info["time_relative"]
    init_dict["protocol"] = packet_info["protocol"]
    init_dict["src_port"] = packet_info["src_port"]
    init_dict["dst_port"] = packet_info["dst_port"]
    for i in cartesian_product(directions, ["tot"], type):
        init_dict[i] = 0
    for i in cartesian_product(directions, ["iat", "pkt_size"]):
        init_dict[i] = IncStats()
    for i in cartesian_product(directions, ["flags"]):
        init_dict[i] = np.zeros(8, dtype="int32")

    return init_dict


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


def save_flow(output_file, flows, feature_names):
    file = open(output_file, "w")
    file.write(",".join(feature_names))
    file.write("\n")
    n = {1, 25, 50, 75, 99}
    for i in sorted(flows.keys()):
        flow = flows[i]
        # the first 8 features have same name
        file.write(",".join(str(flow[x]) for x in feature_names[:8]))
        file.write(",")
        # write the distributions
        for j in range(4):
            file.write(",".join(
                # 8+j*5 so we get the name of distribution, [:-2] to remove the percentile from feature name
                str(x) for x in flow[feature_names[8 + j * 6][:-5]].get_statistics() ))
            file.write(",")
        file.write(",".join(str(x) for x in flow['fwd_flags']))
        file.write(",")
        file.write(",".join(str(x) for x in flow['bwd_flags']))
        file.write("\n")
    file.close()


def flow_meter(pcap_file):
    flows = {}
    directions = ["fwd", "bwd"]
    ports = ["src", "dst"]
    type = ["pkt", "byte"]
    dist_features = ["mean","std","skewness","kurtosis","min","max"]
    flags = ["FIN", "SYN", "RST", "PUSH", "ACK", "URG", "CWE", "ECE"]
    # quickly create field names by using cartesian product of strings
    feature_names = ["duration", "protocol"] + \
        cartesian_product(ports, ["port"]) + cartesian_product(directions, ["tot"], type) + \
        cartesian_product(directions, ["pkt_size"], dist_features) + cartesian_product(directions, ["iat"], dist_features) + \
        cartesian_product(directions, flags, ["cnt"])

    cap = pyshark.FileCapture(pcap_file)
    for packet in cap:
        if packet.highest_layer == "TCP":
            # print(dir(packet.tcp))
            stream_id = packet.tcp.stream
            info = tcp_extractor(packet.tcp)

            if stream_id not in flows.keys():
                flows[stream_id] = init_stream(info)
            update_stream(info, flows[stream_id])
    save_flow("slowloris_flow.csv", flows, feature_names)


if __name__ == '__main__':
    flow_meter(sys.argv[1])
