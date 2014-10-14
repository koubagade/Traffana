


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

static int int_read = 0;
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void *live_print( void *arg);

void print_app_usage(void);

/* Global variables */
	int unsigned long epoch_time = 1000000;
	int readflag = 0;
    int interfaceflag = 0;
    int writeflag =0;
    int verboseflag =0;
    int timeflag = 0;
    int unsigned long timevalue;
/*        
    char* readvalue = NULL;
    char* interfacevalue = NULL;
    char* writevalue = NULL;
    char* verbosevalue = NULL;
    int max_width = 8;
*/

	int readvalue = 0;
    int interfacevalue = 0;
    int writevalue = 0;
    int verbosevalue = 0;
    int max_width = 8;
/* got packet variables */
	int count = 0;                   /* packet counter */
	int unsigned long start_time;
	int start_time_sec;
	int start_time_usec;
	int unsigned long time_in, time_usec; 
	int unsigned long time_sec;
	int size_payload = 0 ;
	int tcp_packet_counter = 0;
	int udp_packet_counter = 0;
	int icmp_packet_counter = 0;
	int default_packet_counter = 0;
	int first_flag = 0;
	
	FILE *write_file; 
	
	pthread_t threadname;



void print_app_usage(void)
{

	printf("Usage: -r [filename] -w [filename] -T [epoch_time_value] -i [interface] -v \n");
	printf("\n");
	return;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	
	
	/* declare pointers to packet headers */
	/*const struct sniff_ethernet *ethernet;   The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	
	
	
	int size_ip;
	
	
	
	
	
	/* define ethernet header 
	ethernet = (struct sniff_ethernet*)(packet); */
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	time_usec = (int unsigned long) header->ts.tv_usec;
	time_sec = (int unsigned long) header->ts.tv_sec;
	time_in = 1000000* time_sec + time_usec;

	if(first_flag == 0)
	{
              int_read = 1;
		first_flag =1; 
		start_time = time_in;
		start_time_sec = time_sec;
		start_time_usec = time_usec;
	}
	
	while(time_in > start_time + epoch_time)
	{
		if (verboseflag != 1)
		{
			if (writeflag ==1)
			{
				fprintf(write_file,"%lf   %*d    %*d\n", (double)start_time * 0.000001, max_width, count, max_width, size_payload);
				fflush(write_file);
			}
			else
			{
				printf("%lf   %*d    %*d\n", (double)start_time * 0.000001, max_width, count, max_width, size_payload);
			}
			
			
			
			start_time = start_time + epoch_time;
			count = 0;
			size_payload = 0;
		}
		else 
		{
			if (writeflag == 1)
			{
				fprintf(write_file,"%lf %*d %*d %*d %*d %*d %*d\n",(double)start_time * 0.000001, max_width, count, max_width, size_payload, max_width, tcp_packet_counter, max_width, udp_packet_counter,max_width, icmp_packet_counter, max_width, default_packet_counter);
				fflush(write_file);
				}
			else
			{
				printf("%lf %*d %*d %*d %*d %*d %*d\n",(double)start_time * 0.000001, max_width, count, max_width, size_payload, max_width, tcp_packet_counter, max_width, udp_packet_counter,max_width, icmp_packet_counter, max_width, default_packet_counter );
			}
			
			start_time = start_time + epoch_time;
			count = 0;
			size_payload = 0;
			tcp_packet_counter = 0; 
			udp_packet_counter = 0;
			icmp_packet_counter = 0;
			default_packet_counter = 0;
		}
	} 

	size_payload = size_payload + header->len;
	count++;
	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			tcp_packet_counter++;
			break;
		case IPPROTO_UDP:
			udp_packet_counter++;
			return;
		case IPPROTO_ICMP:
			icmp_packet_counter++;
			return;
		default:
			default_packet_counter++;
			return;
	}
	

return;
}

void *live_print( void *arg)
{ 
       while (int_read == 0) 
       {
            continue;
       }
	//usleep(1000000);
	while (1)
	{
		if (verboseflag != 1)
			{
				if (writeflag ==1)
				{
					fprintf(write_file,"%lf   %*d    %*d\n", (double)start_time * 0.000001, max_width, count, max_width, size_payload);
					fflush(write_file);
				}
				else
				{
					printf("%lf   %*d    %*d\n", (double)start_time * 0.000001, max_width, count, max_width, size_payload);
				}
				
				//printf("packet count = %d ", count);
				//printf("payload = %d\n", size_payload);
				
				start_time = start_time + epoch_time;
				count = 0;
				size_payload = 0;
			}
		else 
			{
				if (writeflag == 1)
				{
					fprintf(write_file,"%lf %*d %*d %*d %*d %*d %*d\n",(double)start_time * 0.000001, max_width, count, max_width, size_payload, max_width, tcp_packet_counter, max_width, udp_packet_counter,max_width, icmp_packet_counter, max_width, default_packet_counter);
					fflush(write_file);
				}
				else
				{
					printf("%lf %*d %*d %*d %*d %*d %*d\n",(double)start_time * 0.000001, max_width, count, max_width, size_payload, max_width, tcp_packet_counter, max_width, udp_packet_counter,max_width, icmp_packet_counter, max_width, default_packet_counter );
				}//printf("packet count = %d ", count);
				//printf("payload = %d\n", size_payload);
				
				start_time = start_time + epoch_time;
				count = 0;
				size_payload = 0;
				tcp_packet_counter = 0; 
				udp_packet_counter = 0;
				icmp_packet_counter = 0;
				default_packet_counter = 0;
				
			}
		usleep(epoch_time);
	}
	return(0);
}

int main(int argc, char *argv [])
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;		/* number of packets to capture */
    int c = 1;
      

	while (c < argc )
	{
		//printf("%s ",argv[c]);
		if ( strcmp ( argv[c], "--verbose") == 0)
		{
				verboseflag = 1;
				c++;
		}
		else if  (strcmp (argv[c], "-v") == 0)
		{
				verboseflag = 1;
				c++;
		}
		else if (strcmp ( argv[c], "--interface") == 0) 
		{
			interfaceflag = 1;
			c++;
			interfacevalue = c;
			c++;
		}
		else if  (strcmp (argv[c], "-i") == 0)
		{
			interfaceflag = 1;
			c++;
			interfacevalue = c;
			c++;
		}	
		else if (strcmp ( argv[c], "--read") == 0) 
		{
			readflag = 1;
			c++;
			readvalue = c;
			c++;
		}
		else if  (strcmp (argv[c], "-r") == 0)
		{
			readflag = 1;
			c++;
			readvalue = c;
			c++;
		}	
		else if (strcmp ( argv[c], "--write") == 0) 
		{
			writeflag = 1;
			c++;
			writevalue = c;
			write_file = fopen ( argv[c], "w+");
			c++;
		}
		else if  (strcmp (argv[c], "-w") == 0)
		{
			writeflag = 1;
			c++;
			writevalue = c;
			write_file = fopen ( argv[c], "w+");
			c++;
		}
		else if (strcmp ( argv[c], "--time") == 0) 
		{
			timeflag = 1;
			c++;
			timevalue = atof (argv[c]);
			epoch_time = (int unsigned long)timevalue * epoch_time;
			c++;
		}
		else if  (strcmp (argv[c], "-T") == 0)
		{
			timeflag = 1;
			c++;
			timevalue = atof (argv[c]);
			epoch_time = (int unsigned long)timevalue * epoch_time;
			c++;
		}
		else 
		{
			printf ("Unrecognized option\nTry again\n.");
			exit(0);
		}	
	}
	//printf("\n verbose flag = %d\n", verboseflag);
	//printf("\n  wflag = %d, wvalue = %s\n", writeflag, argv[writevalue]);
	//exit(0);








     
 //printf ("rflag = %d, rvalue = %s, tflag = %d, tvalue = %lu\n",readflag, argv[readvalue], timeflag, epoch_time);

	if (readflag ==1 && interfaceflag == 1 )
	{
		printf("Capture live or from file? Cant do both at the same time.....\nTry Again\n\n");
		exit(0);
	}

	if (timeflag == 1 && timevalue == 0 )
	{
		printf("You used time option without providing value... \nTry again.\n");
		exit(0);
	}
	if (interfaceflag == 1 && argv[interfacevalue] == NULL )
	{
		printf("You used interface option without providing value... \nTry again.\n");
		exit(0);
	}




	/* check for capture device name on command-line */
	if (interfaceflag == 1) {
		
		handle = pcap_open_live(argv[interfacevalue], SNAP_LEN, 1, 1000, errbuf);

	/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
			net = 0;
			mask = 0;
		}
	}

	
	/* open capture device */
	else if (readflag == 1) {
		handle = pcap_open_offline(argv[readvalue], errbuf);
              int_read = 1;
	}	
	else {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	
	

	
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[interfacevalue], errbuf);
		exit(EXIT_FAILURE);
	}

 
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	pthread_create(&threadname , NULL, &live_print, NULL);
	/* now we can set our callback function */

	pcap_loop(handle, num_packets , got_packet, NULL);
	
			
		if (verboseflag != 1)
		{
			if (writeflag ==1)
			{
				fprintf(write_file,"%lf   %*d    %*d\n", (double)start_time * 0.000001, max_width, count, max_width, size_payload);
				fflush(write_file);
			}
			else
			{
				printf("%lf   %*d    %*d\n", (double)start_time * 0.000001, max_width, count, max_width, size_payload);
			}
			
			//printf("packet count = %d ", count);
			//printf("payload = %d\n", size_payload);
			
			start_time = start_time + epoch_time;
			count = 0;
			size_payload = 0;
		}
		else 
		{
			if (writeflag == 1)
			{
				fprintf(write_file,"%lf %*d %*d %*d %*d %*d %*d\n",(double)start_time * 0.000001, max_width, count, max_width, size_payload, max_width, tcp_packet_counter, max_width, udp_packet_counter,max_width, icmp_packet_counter, max_width, default_packet_counter);
				fflush(write_file);
			}
			else
			{
				printf("%lf %*d %*d %*d %*d %*d %*d\n",(double)start_time * 0.000001, max_width, count, max_width, size_payload, max_width, tcp_packet_counter, max_width, udp_packet_counter,max_width, icmp_packet_counter, max_width, default_packet_counter );
			}//printf("packet count = %d ", count);
			//printf("payload = %d\n", size_payload);
			
			start_time = start_time + epoch_time;
			count = 0;
			size_payload = 0;
			tcp_packet_counter = 0; 
			udp_packet_counter = 0;
			icmp_packet_counter = 0;
			default_packet_counter = 0;
		}
	
	

	
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	fclose(write_file);

	//printf("\nCapture complete.\n");

return 0;
}

