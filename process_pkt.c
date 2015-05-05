#include "bouncer.h"

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

	/* Ethernet header */
struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
};

	/* IP header */
struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};


void process_pkt(u_char *args, const struct pcap_pkthdr *header,
	const u_char *p){

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(p);
	ip = (struct sniff_ip*)(p + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* Check IP version */
	if (IP_V(ip) != 4) {
		printf("Invalid IP version (not 4).");
		return;
	}

	/* Check if TTL is zero */
	if (ip->ip_ttl == 0) {
		printf("TTL is zero, packet discard");
		return;
	}

	/* determine protocol */
	// For ICMP and TCP, we continue the checking. For others protocols, we leave the function.

	u_int protocol;
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			// Appel fonction TCP
			protocol = 6;
			break;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			// Appel fonction ICMP
			protocol = 1;
			break;
		default:
			printf("Protocol not taken in charge.\n");
			return;
	}

	/* Size of the payload of the IP packet */
	
	if((ip->ip_len)>size_ip){
		u_int size_ip_payload = (ip->ip_len) - size_ip;
	}
	else{
		printf("   * Invalid IP total length: %u bytes\n", (ip->ip_len));
		return;
	}
	// tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	// size_tcp = TH_OFF(tcp)*4;
	// if (size_tcp < 20) {
	// 	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	// 	return;
	// }

	
	

	payload = (u_char *)(p + SIZE_ETHERNET + size_ip + size_tcp);

	printf("a packet received of length: %u", size_ip);

	

	
	/* Define pointers for packet's attributes */
	
	/* Check IP header*/

	/* Check type of packet and process*/

	
	/* Check ICMP header*/
	/* Check TCP header*/
	/* Check FTP header*/

	/* Send processed packet */
};


