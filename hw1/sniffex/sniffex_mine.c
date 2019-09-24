/**
 * NOTE: This source code follows the tutorial as stated in this website: https://www.tcpdump.org/pcap.html
 * also, the tutorial seems to work closely with BSD. 
 * 
 * On other platforms, instead of using u_char identifier, use `unsigned char` instead!
 */

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


/**
 * char *device         = device specified when running main function.
 * int snaplen          = integer which defines the max number of bytes to be capturd by pcap
 * int promisc          = when set to true, brings the interface into promiscuous mode (however, even if it is set to false, it is possible under specific cases for the interface to be in promiscuous mode, anyway)
 * int to_ms            = read time out in milliseconds (a value of 0 means no time out; on at least some platforms, this means that you may wait until a sufficient number of packets arrive before seeing any packets, so you should use a non-zero timeout).
 * char *ebuf           = a string we can store any error messages without.
 * 
 * @returns: session handler
 * 
 * @NOTE: about promiscuous vs non-promiscuous sniffing: the 2 techniques are very different in style.
 *      Non-promiscuous: sniff only traffic that is directly related to it (traffic to, from, or routed through the host)
 *      Promiscuous: sniffs all traffic on the wire 
 *              DRAWBACKS
 *              --------------------
 *              - detectable -- the target host can test with strong reliability 
 *                to determine if another host is doing promiscuous sniffing
 *              - only works in a non-switched environment -- hub/switch that is 
 *                being ARP flooded
 *              - on high traffic networks, the host can become quite taxed for 
 *                system resource
 */
pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms,
	    char *ebuf);

/**
 * pcap_t *p                = session handler, that has the class pcap_t, as above
 * struct bpf_program *fp   = reference to the place that will store the compiled version of our filter
 * char *str                = expression in regular string format
 * int optimize             = decides if the expression should be "optimized" or not (0 = false, 1 = true)
 * bpf_u_int32 netmask      = network mask of the network the filter applies to
 * 
 * @returns: -1 on failure; all other values indicate success
 * 
 * @NOTE: After the expression has been compiled, it is time to apply it. Run int pcap_setfilter(pcap_t *p, struct bpf_program *fp).
 */
int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize,
    bpf_u_int32 netmask);


/**
 * pcap_t *p                = session handler
 * struct bpf_program *fp   = reference to the compiled version of the expression (or filter)
 */
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);


/**
 * @desc: capture a single packet
 * 
 * pcap_t *p                = session handler
 * struct pcap_pkthrdr *h   = pointer a structure that holds general information about the packet
 *                      specifically the time in which it was sniffed, the length of this packet,
 *                      and the length of this specific portion (in case it is fragmented)
 * @returns: u_char pointer to the packet that is described by this structure
 * 
 * @NOTE:   Few sniffers (if any) actually use pcap_next().
 *              More often than not, they use pcap_loop() or pcap_dispatch() 
 *              (which then themselves use pcap_loop())
 */
unsigned char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);


/**
 * @desc: This is a callback function
 * 
 * pcap_t *p                = session handler
 * int cnt                  = a counter that tells pcap_loop() how many packets it should sniff for
 *                              before returning (a negative value means it should sniff until an error occurs)
 * pcap_handler callback    = name of the callback function (just its identifier, no parantheses)
 * unsigned char *user      = it is a useful argument, but usually set as NULL. This array will contain
 *                              a set of our arguments that we want to send to the callback function.
 *                              Obviously, we need to typecast to a unsigned char pointer to ensure the results make it there correctly.
 *                              pcap actually makes use of some very interesting means of passing information in the form of a 
 *                              unsigned char pointer.
 */
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, unsigned char *user);

/**
 * format of our callback function
 * 
 * unsigned char *args      = first argument corresponds to the last argument of pcap_loop (unsigned char *user)
 *                              Whatever is passed as the last argument to pcap_loop() is passed to the first argument of our callback function 
 *                              everytime the function is called
 * const struct pcap_pkthdr = contains information about when the packet was sniffed, how large it is, etc.
 *                              The pcap_pkthdr structure is defined in pcap.h as :
 *                              struct pcap_pkthdr {
 *                                  struct timeval ts; // time stamp
 *                                  bpf_u_int32 caplen; // length of portion present
 *                                  bpf_u_int32 len; // length this packet (off wire) 
 *                              };
 * const unsigned char *packet  = (Most important, and most interesting): It is another pointer to an unsigned char, and it points
 *                                                                      to the first byte of a chunk of data containing the entire packet, as sniffed by pcap_loop().
 *                                                                      This argument is a collection of structures (e.g. TCP/IP packet would have: (1) Ethernet header, (2) IP header, (3) TCP header, (4) packet's payload)
 *                                                                      This pointer points to the serialized version of these structures.
 *                                                                      To make any use out of it, we need to do some INTERESTING TYPECASTING.
 * 
 * To use *packet properly, we need to have the actual structures defined before we can typecast to them.
 * The structure after this function is a structure definition the author has used to describe a TCP/IP packet over Ethernet.

 * @returns: void. This is logical because the pcap_loop() wouldn't know how to handle a return value anyway.
 */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
    const unsigned char *packet);

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
    unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    unsigned short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    unsigned char ip_vhl; /* version << 4 | header length >> 2 */
    unsigned char ip_tos; /* type of service */
    unsigned short ip_len; /* total length */
    unsigned short ip_id; /* identification */
    unsigned short ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    unsigned char ip_ttl; /* time to live */
    unsigned char ip_p; /* protocol */
    unsigned short ip_sum; /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef unsigned int tcp_seq;
struct sniff_tcp {
    unsigned short th_sport; /* source port */
    unsigned short th_dport; /* destination port */
    tcp_seq th_seq; /* sequence number */
    tcp_seq th_ack; /* acknowledgement number */
    unsigned char th_offx2; /* data offset, rsvd */
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    unsigned char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short th_win; /* window */
    unsigned short th_sum; /* checksum */
    unsigned short th_urp; /* urgent pointer */
};

/* defining the variables and compile-time definitions we will need to deconstruct the packet data */
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */
    unsigned int size_ip;
    unsigned int size_tcp;

    

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

    
	

    
    pcap_t *handle;/* Session handle */
    char dev[] = "rl0";                                         /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];                              /* Error string */
    struct bpf_program fp;                                      /* The compiled filter expression */
    char filter_exp[] = "port 23";                              /* The filter expression */
    bpf_u_int32 mask;                                           /* The netmask of our sniffing device */
    bpf_u_int32 net;                                            /* The IP of our sniffing device */
    
    /* using pcap_next() to sniff a packet */
    struct pcap_pkthdr header;                                  /* The header that pcap gives us */
    const unsigned char *packet;                                       /* The actual packet */

    /* magical typecasting */
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf(" * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    /**
     * For the sake of simplicity, we'll say that the address this pointer is set to is the value X. Well, if our three structures are just sitting in
     * line, the first of them (sniff_ethernet) being located in memory at the address X, then we can easily find the address of the structure
     * after it; that address is X plus the length of the Ethernet header, which is 14, or SIZE_ETHERNET.
     * 
     * ***
     * The IP header, unlike the Ethernet header, does not have a fixed length; its length is given, as a count of 4-byte words,
     * by the header length field of the IP header. As it's a count of 4-byte words, it must be multiplied by 4 to give the size in bytes. The 
     * minimum length of that header is 20 bytes.
     * 
     * ***
     * The TCP header also has a variable length; its length is given, as a number of 4-byte words, by the "data offset" field of the TCP
     * header, and its minimum length is also 20 bytes.
     */
    payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    
    /**
     * @returns: one of its IPv4 Network numbers and corresponding network mask (the network number is the 
     *          IPv4 address && network mask, so it contains only the network part of the address)
     * 
     * @NOTE: The return value is essential because we needed to know the network mask in order to apply the filter.
     *          This function is described in the Miscellaneous section at the end of the document.
     */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) /* Find the properties for the device */ {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /**
     * In this example, handle object opens the device at stored in the "dev" argument,
     * tells it to read however many bytes that are specified in BUFSIZ (which is defined in pcap.h)
     * We are telling it to put the device into promiscuous mode, to sniff until an error occurs, and
     * if there is an error, store it in the string errbuf.
     */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  /* Open the session in promiscuous mode */
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    
    /* And close the session */
    pcap_close(handle);
    //return(0);

    /**
     * If your program doesn't support the link-layer header type provided by the device,
     * it has to give up; this would be done with code
     */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }
    
	return(0);
}