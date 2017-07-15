#include <pcap.h>
#include <stdio.h>
#define SIZE_ETH 14						//ethernet length
#define IP_LEN(ip)  (((ip)->ver_len) & 0x0f)		//ip length
#define IP_V(ip)    (((ip)->ver_len) >> 4)			//ip version
#define TH_LEN(tcp) (((tcp)->Off_set & 0xf0) >> 4)	//tcp length

struct eth_header{
	unsigned char eth_Sourse_host[6];
	unsigned char eth_Dest_host[6];
	unsigned short eth_type;
};
struct ip_header{
	unsigned char ver_len;
	unsigned char servivce;
	unsigned short Total_Length;
	unsigned short Idntification;
	unsigned short Offset;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short Checksum;
	unsigned long Sourse_IP;
	unsigned long Dest_IP;
};
struct tcp_header{
	unsigned short Sourse_Port;
	unsigned short Dest_Port;
	unsigned long Seq;
	unsigned long Ack;
	unsigned short Off_set;
	unsigned short Window_size;
	unsigned short Checksum;
	unsigned short Urget_point;
};

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	const struct eth_header *eth;
	const struct ip_header *ip;
	const struct tcp_header *tcp;
	const char *payload;
	unsigned int size_ip;
	unsigned int size_tcp;
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
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
	/* Grab a packet */
	while(1){
		packet = pcap_next(handle, &header);
		eth = (struct eth_header*)(packet);
		ip = (struct ip_header*)(packet+SIZE_ETH);
		size_ip = IP_LEN(ip)*4;
		if(size_ip < 20){
			printf("%d less length ip \n", size_ip);
		}
		tcp = (struct tcp_header*)(packet+SIZE_ETH+size_ip);
		size_tcp = TH_LEN(tcp)*4;
		if(size_tcp < 20){
			printf("%d less length tcp \n", size_tcp);
		}
		payload = (unsigned char *)(packet + SIZE_ETH + size_ip + size_tcp);
		printf("===============================\n");
		printf("%x ethernet d-port \n", htons(eth->eth_Sourse_host));
		printf("%x ethernet s-port \n", htons(eth->eth_Dest_host));
		printf("%d.%d.%d.%d source ip \n", (htonl(ip->Sourse_IP) & 0xff000000) >> 24, (htonl(ip->Sourse_IP) & 0x00ff0000) >> 16, (htonl(ip->Sourse_IP) & 0x0000ff00) >> 8, (htonl(ip->Sourse_IP) & 0x0000ff));		//done
		printf("%d.%d.%d.%d source ip \n", (htonl(ip->Dest_IP) & 0xff000000) >> 24, (htonl(ip->Dest_IP) & 0x00ff0000) >> 16, (htonl(ip->Dest_IP) & 0x0000ff00) >> 8, (htonl(ip->Dest_IP) & 0x0000ff));			//done
		printf("%d source port \n", htons(tcp->Sourse_Port));		//done
		printf("%d dest port \n", htons(tcp->Dest_Port));			//done
		printf("%x data \n \n", payload);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		printf("\n ===============================\n \n");
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
