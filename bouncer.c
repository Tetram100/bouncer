/* Port Bouncer
* To be called as nbouncer local_ip local_port remote_ip remote_port
*/

#include "bouncer.h"
#include "dict.h"

void process_pkt(u_char *args, const struct pcap_pkthdr *header,
	const u_char *packet);

struct process_argument{
	bpf_u_int32 bouncer_address;
	bpf_u_int32 server_address;
	// hashmap
};


int main(int argc, char *argv[]) {

		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "icmp";	/* The filter expression */ //TODO ajouter TCP dans filtre.
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

	if (argc > 1) {
		dev = argv[1];
	} else {
		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
		}
	}
	fprintf(stderr, "Interface used %s\n", dev);

		/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
		/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
	
	// TODO envoyer les bonnes adresses.
	struct process_argument argument;
	argument.bouncer_address = net;
	argument.server_address = net;

	/* Last argument give a pointer to other arguments that we need : the address of the bouncer, the address of the server, the "hashmap" */
	pcap_loop(handle, -1, process_pkt, (u_char*) &argument);

	return 0;
}//End of the bouncer
