#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#define SIZE_ETH 14						//ethernet length
#define IP_LEN(ip)  (((ip)->ver_len) & 0x0f)		//ip length
#define IP_V(ip)    (((ip)->ver_len) >> 4)			//ip version
#define TH_LEN(tcp) (((tcp)->Off_set & 0xf0) >> 4)	//tcp length
#define ETHERTYPE_IP 0x0800
#define PROTOCOL_ID 6

struct eth_header{
	uint8_t eth_Sourse_host[6];
	uint8_t eth_Dest_host[6];
	uint16_t eth_type;
};
struct ip_header{
	uint8_t ver_len;
	uint8_t servivce;
	uint16_t Total_Length;
	uint16_t Idntification;
	uint16_t Offset;
	uint8_t TTL;
	uint8_t protocol;
	uint16_t Checksum;
	uint32_t Sourse_IP;
	uint32_t Dest_IP;
};
struct tcp_header{
	uint16_t Sourse_Port;
	uint16_t Dest_Port;
	uint32_t Seq;
	uint32_t Ack;
	uint16_t Off_set;
	uint16_t Window_size;
	uint16_t Checksum;
	uint16_t Urget_point;
};
void mac_address(char *mac){
	for(int i = 0; i < 6; i++){
		if(i == 5){
			printf("%02x\n",mac[i] & 0x000000ff);
		}
		else{
			printf("%02x-", mac[i] & 0x000000ff);
		}
	}
}
int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;				/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;			/* Our netmask */
	bpf_u_int32 net;			/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	const struct eth_header *eth;
	const struct ip_header *ip;
	const struct tcp_header *tcp;
	const char *payload;
	unsigned int size_ip;
	unsigned int size_tcp;
	unsigned int size_data;
	char buf[20];
	int res=0;
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (argv[1] == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
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
	while((res = pcap_next_ex(handle, &header, &packet)) >= 0){
		if (res == 0){
			continue;
		}else if(res <= -1){
			printf("EOF \n");
			continue;
		}
		eth = (struct eth_header*)(packet);
		if(ntohs((struct eth_header*)eth->eth_type) == ETHERTYPE_IP){
			ip = (struct ip_header*)(packet+SIZE_ETH);
			size_ip = IP_LEN(ip)*4;
		}else{
			continue;
		}
		if((struct ip_header*)ip->protocol == PROTOCOL_ID){
			tcp = (struct tcp_header*)(packet+SIZE_ETH+size_ip);
			size_tcp = TH_LEN(tcp)*4;
		}else{
			continue;
		}
		size_data = ntohs(ip->Total_Length) - size_ip - size_tcp;
		if(size_data <= 0){
			continue;
		}
		payload = (uint8_t *)(packet + SIZE_ETH + size_ip + size_tcp);
	
		printf("===============================\n");
		printf("ethernet s-address:");
		mac_address(eth->eth_Sourse_host);		//done
		printf("ethernet d-address:");
		mac_address(eth->eth_Dest_host);		//done
		inet_ntop(AF_INET, (void *)&ip->Sourse_IP, buf, sizeof(buf));
		printf("sourse ip: %s \n", buf);			//done
		inet_ntop(AF_INET, (void *)&ip->Dest_IP, buf, sizeof(buf));
		printf("Dest ip: %s \n", buf);			//done
		printf("source port: %d \n", ntohs(tcp->Sourse_Port));		//done
		printf("dest port: %d \n", ntohs(tcp->Dest_Port));		//done
		printf("data size: %d \n", size_data);
		
		printf("\n");
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		printf("===============================\n \n");
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
