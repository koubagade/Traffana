all:traffana.c
	gcc -o traffana traffana.c -lpcap -pthread
clean:
	rm -f *.o traffana 
