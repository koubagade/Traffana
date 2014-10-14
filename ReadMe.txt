University of Southern California
Viterbi School of Engineering
Computer Science Department

Name: Koustubh Prasanna Bagade
USC ID: 2633985567

Course: CSCI 551:Computer Communications
Assignment: Homework 1

Files included in tarball:
1. traffana.c
2. Readme.txt
3. makefile

Objective:
To create packet capturing tool that is used to analyse network traffic.
The tool captures live IP packets and lists total number of packets and total data in bytes in predefined intervals.
The tool can read through tcpdump files and show the results.

Tool name: Trafana
File name: KB_Assignment1.c

Commands to run the tool:

	Compilation:
		gcc -Wall -o trafana KB_Assignment1.c -lpcap -lpthread
		
	Execution: 
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

References.
1. libpcap/tcpdump pages
2. stackoverflow examples
3. Linux man pages

	