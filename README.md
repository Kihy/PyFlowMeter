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

## Flow meter logic
The flowmeter is based on observer pattern and consists of two modules:
- the streaming interface, which reads packets and notifies the observer (this is the observable). Currently only offline interface(reading from pcap file) is created, and you can easily write real time interface by implementing the StreamingInterface interface.
- the flow meter, which gets notified by the streaming interface of a packet coming in. The flow meter keeps are flow dictionary of current flow, initializes an empty flow when a new flow is found(for tcp connections it is determined by stream index of tshark), or updates if it is an ongoing flow. To save memory when processing large datasets, if a tcp flow was not updated in a certain amount of time (currently 600 seconds), it is considered as finished and is saved to file and removed from flow dictionary. Once the interface has finished it stores all current flows to file and exits.

## Requirements
The main code requires numpy and pyshark which can be installed with pip, and tshark which can be installed with apt-get
The testing code requires scipy for statistics calculation.


## Running the flowmeter
To run, clone this repo, modify last few lines on PyFlowMeter.py and run

```
python3 PyFlowMeter.py {path_to_pcap} {output_file_path}
```
and the output is at output_file_path

This repo also contains slowloris.pcap, which is a sample traffic pcap file captured during slowloris attack and slowloris_flow.csv is the extracted flow from the pcap file.
