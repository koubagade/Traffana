Traffana
========

A Network Traffic Analyser

University of Southern California

Viterbi School of Engineering

Computer Science Department

Name: Koustubh Prasanna Bagade

Course: CSCI 551:Computer Communications

Objective:
To create packet capturing tool that is used to analyse network traffic.
The tool captures live IP packets and lists total number of packets and total data in bytes in predefined intervals.
The tool can read through tcpdump files and show the results.

Tool name: Trafana

Commands to run the tool:

1. Manual Compilation:

		gcc -Wall -o trafana traffana.c -lpcap -lpthread

2. Auto compilation:

		make
		
3.Execution: 
		sudo ./trafana -r[input_filename] -T[Epoch_time] -w [output_filename] -v
		
	Options:
	1. -r / --read [input_filename]
	2. -T / --time [Epoch_time]
	3. -w / --write [output_filename]
	4. -i / --interface [interface_name]
	5. -v / --verbose to start verbose mode
	
Output format:
1. Without verbose mode

	Time_stamp  #total_packets total_bytes
	
2. With verbose mode

	Time_stamp #total_packets total_bytes #TCP_packets #UDP_packets #ICMP_packets #Other_packets 

