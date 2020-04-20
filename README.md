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

-   the streaming interface, which reads packets and notifies the observer (this is the observable). Currently only offline interface(reading from pcap file) is created, and you can easily write real time interface by implementing the StreamingInterface interface.
-   the flow meter, which gets notified by the streaming interface of a packet coming in. The flow meter keeps are flow dictionary of current flow, initializes an empty flow when a new flow is found(for tcp connections it is determined by stream index of tshark), or updates if it is an ongoing flow. To save memory when processing large datasets, if a tcp flow was not updated in a certain amount of time (currently 600 seconds), it is considered as finished and is saved to file and removed from flow dictionary. Once the interface has finished it stores all current flows to file and exits.

## Requirements

The main code requires numpy, tqdm and pyshark which can be installed with pip, and tshark which can be installed with apt-get
The testing code requires scipy and pandas for statistics calculations and various checks.

## Running the flowmeter

To run, clone this repo, modify last few lines on PyFlowMeter.py and run

    python3 PyFlowMeter.py {path_to_pcap} {output_file_path}

and the output is at output_file_path

there are commands such as:

-   \-r to indicate batch processing of all files under directory and output to output directory
-   \-i to indicate how often to check timeouts
-   \-t to indicate timeout
-   \-l to indicate how many flows to check each time.

This repo also contains tests/pcap_file folder, which contains some sample traffic pcap file captured during slowloris attack and normal traffic. These are mainly used for testing but you could use it as sample.

Also note that in v0.4.2.11 of pyshark, if you set only_summaries=True for FileCapture, it will miss the first packet. To solve this issue you would have to go to \_packets_from_tshark_sync() function in capture.py and remove data = b''

## implementation Details

-   The offline version of the flow meter relies on tshark's internal stream indexes to determine flows. For real time interface, probably need to create 5 tuples as index.
-   The flow meter currently only checks TCP and UDP packets.
-   The packet size attribute is the size of the entire packet, rather than size of tcp payload. This is done so that we can compare with wireshark conversations.
-   The ordering of flows generated is by its finishing time, or if multiple flows have finished it is by start time.
-   In order to speed up the process, only_summaries is set to True in FileCapture(), this significantly increases the packet generation time, however, the default fields for only_summaries does not include stream index and other fields, thus we have to do the following:
    -   the summaries are specified by psml file, which is linked to wireshark's gui column interface. Whatever attribute is displayed in wireshark's column interface is displayed by only_summaries.
    -   The easiest way is to open wireshark's gui interface and get all the important fields on the columns.
    -   Then go to help -> about wireshark -> folders -> preferences and search gui.column.format and copy the string.
    -   In FileCapture, specify custom_parameters to {'-o', 'gui.column.format:{string}'}
    -   Note that some fields common but have to be specified seperately for tcp and udp.
-   When processing DoS datasets the timeout should set to a low number, otherwise the number of flows stored will be large and the speed of processing reduces significantly. In real time interfaces it is unneccesary.
-   For nmap scan the flags field may be reserved set to 100, in this case we ignore it.

## Speed Boost

When processing large files, the naive approach is extremely slow, since it has to process all flows for each packet arrival. To speed things up, there is a field that reduces the frequency of checking (-i).

To further boost the speed, a Ordered dict is used instead of original dict. Once a new flow is generated, it is added at the end, once a flow is updated it is moved to the end (this operation is O(1), similar to linked list). This means we only have to check the first few flows at the head of the dictionary, as they will have not being updated in the longest time. The number of flows to check is specified with -l.  
