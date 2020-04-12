# PyFlowMeter


Custom network traffic extractor to extract flows from pcap data.
Currently only extracts tcp features and is work in progress
The features extracted are:

| feature name               | description                                       | number of features |
| -------------------------- | ------------------------------------------------- | ------------------ |
| duration                   | total duration of flow                            | 1                  |
| protocol                   | protocol used for the flow                        | 1                  |
| {dst,src}\_port            | destination and source port number                | 2                  |
| {fwd,bwd}\_tot\_{pkt,byte} | total number of forward/backward packet and bytes | 2 \* 2             |
| {fwd,bwd}_pkt_size_{n}     | distribution of fwd/bwd packet size               | 2 \* 5             |
| {fwd,bwd}_iat_{n}          | distribution of fwd/bwd inter arrival time        | 2 \* 5             |
| {fwd,bwd}\_{flags}\_cnt    | number of packets with various flags              | 2 \* 8             |

They are based on CICFlowMeter

## Running the flowmeter
To run, clone this repo and run

```
python3 py_flow_meter.py {path_to_pcap}
```
and the output is at the directory of the script.

This repo also contains slowloris.pcap, which is a sample traffic captured during slowloris attack and slowloris_flow.csv is the extracted flow from the pcap file.
