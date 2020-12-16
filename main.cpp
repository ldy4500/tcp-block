#include <cstdio>
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

struct packet_hdr{
    struct libnet_ethernet_hdr ether_;
    struct libnet_ipv4_hdr ip_;
    struct libnet_tcp_hdr tcp_;
};



char* pattern;
char* dev;
u_int8_t my_mac[6];
const char* block = "block!!!!!";



int getMyMac(char *ifname, uint8_t *mac_addr)
{
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM,0);
	if(sockfd<0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,6);


	close(sockfd);
	return 0;
}

u_short ip_checksum(struct libnet_ipv4_hdr* ip_hdr)
//refer to code review
{
	u_char* raw = (u_char*)ip_hdr;
	int sum = 0;
	
	for(int i = 0 ; i < (ip_hdr->ip_hl * 4) ; i+=2)
	{
		sum += *(u_short*)(raw + i);
	}

	u_short checksum = sum >> 16;
	checksum += sum & 0xffff;

	return checksum ^ 0xffff;
}

u_short tcp_checksum(struct libnet_ipv4_hdr* ip_hdr, struct libnet_tcp_hdr* tcp_hdr)
//refer to code review
{
	u_char* ip_raw = (u_char*)ip_hdr;
	u_char* tcp_raw = (u_char*)tcp_hdr;
	int sum = 0;
	u_short tcp_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);

	for(int i = 12; i < 20; i += 2)
		sum += *(u_short*)(ip_raw + i);

	sum += htons(6);
	sum += htons(tcp_len);

	for(int i = 0 ; i < tcp_len ; i += 2)
	{
		sum += *(u_short*)(tcp_raw + i);
	}

	u_short checksum = sum >> 16;
	checksum += sum & 0xffff;
	return checksum ^ 0xffff;
}

void usage() {
    printf("syntax : tcp_-block <interface> <pattern>\n");
    printf("sample : tcp_-block wlan0 \"Host: test.gilgil.net\"\n");
}

void backward_packet_send(const u_char* packet, pcap_t *handle){

    struct packet_hdr *packet_hdr = (struct packet_hdr*)packet;

    int size = sizeof(struct libnet_ethernet_hdr) + (packet_hdr->ip_.ip_hl * 4) + (packet_hdr->tcp_.th_off * 4) + strlen(block);
	int data_len = ntohs(packet_hdr->ip_.ip_len) - (packet_hdr->ip_.ip_hl * 4) - (packet_hdr->tcp_.th_off * 4);

	struct packet_hdr *new_packet = (struct packet_hdr*)malloc(size);
	memcpy(new_packet, packet_hdr, size);
	memcpy((uint8_t*)&(new_packet->tcp_) + new_packet->tcp_.th_off * 4, block, strlen(block));

	for(int i=0; i<5; i++){
        new_packet->ether_.ether_shost[i] = my_mac[i];
    }
    for(int i=0; i<5; i++){
        new_packet->ether_.ether_dhost[i] = packet_hdr->ether_.ether_shost[i];
    }




    new_packet->ip_.ip_src = packet_hdr->ip_.ip_dst;
	new_packet->ip_.ip_dst = packet_hdr->ip_.ip_src;
    //? why? not my ip?

	new_packet->tcp_.th_sport = packet_hdr->tcp_.th_dport;
	new_packet->tcp_.th_dport = packet_hdr->tcp_.th_sport;
	new_packet->tcp_.th_seq = packet_hdr->tcp_.th_ack;
    
    //printf("%04x",new_packet->tcp_.th_seq)
	
    new_packet->tcp_.th_ack = htonl(ntohl(packet_hdr->tcp_.th_seq) + data_len);
    
    //printf("%04x",new_packet->tcp_.th_ack)



	new_packet->tcp_.th_flags |= 0x11;
    
	new_packet->ip_.ip_len = htons((packet_hdr->ip_.ip_hl * 4) + (packet_hdr->tcp_.th_off * 4) + strlen(block));



	new_packet->ip_.ip_sum = 0;
	new_packet->ip_.ip_sum = ip_checksum(&(new_packet->ip_));
	new_packet->tcp_.th_sum = 0;
	new_packet->tcp_.th_sum = tcp_checksum(&(new_packet->ip_), &(new_packet->tcp_));

	int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&new_packet[0]),size);

	if(res != 0)
		printf("sending backward packet error\n");
        free(new_packet);
        return;

    printf("successfully backward packet sent");

	free(new_packet);
}



void forward_packet_send(const u_char* packet, pcap_t *handle){
    struct packet_hdr *packet_hdr = (struct packet_hdr*)packet;

    int size = sizeof(struct libnet_ethernet_hdr) + (packet_hdr->ip_.ip_hl * 4) + (packet_hdr->tcp_.th_off * 4);
    
    // printf("%d\n", size);

    int length_data = ntohs(packet_hdr->ip_.ip_len) - (packet_hdr->ip_.ip_hl * 4) - (packet_hdr->tcp_.th_off * 4);

    // printf("%d\n", length_data);
    

    struct packet_hdr *new_packet = (struct packet_hdr*)malloc(size);
	memcpy(new_packet, packet_hdr, size);

    for(int i=0; i<5; i++){
        new_packet->ether_.ether_shost[i] = my_mac[i];
    }

	new_packet->ip_.ip_len = htons((packet_hdr->ip_.ip_hl * 4) + (packet_hdr->tcp_.th_off * 4));

	new_packet->tcp_.th_seq = htonl(ntohl(packet_hdr->tcp_.th_seq) + length_data);
	new_packet->tcp_.th_flags |= 0x14;

    //printf("htons((packet_hdr->ip_.ip_hl * 4) + (packet_hdr->tcp_.th_off * 4));


    new_packet->ip_.ip_sum = 0;
	new_packet->ip_.ip_sum = ip_checksum(&(new_packet->ip_));
	new_packet->tcp_.th_sum = 0;
	new_packet->tcp_.th_sum = tcp_checksum(&(new_packet->ip_), &(new_packet->tcp_));

	int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&new_packet[0]),size);



	if(res != 0)
		printf("Sending forward packet error\n");
        free(new_packet);
        return;


    printf("successfully backward packet sent");
	free(new_packet);
}


void block_packet(const u_char* packet, pcap_t *handle){

    struct libnet_ethernet_hdr* ether = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*) (packet + 14);
    struct libnet_tcp_hdr* tcp_ = (struct libnet_tcp_hdr*) (packet + 14 + 20);

    if(ntohs(ether->ether_type) != 0x0800){
        //printf("not ip\n");
        return;
    }
    if(ip->ip_p != 0x06){
        //printf("not tcp_  ");
        return;
    }
    char* data;

    
    int header_size = 54;
    data = (char*)(packet + header_size);

    char* ps = strstr(data,pattern);
	if(ps == NULL){
        //printf("not match\n");
        return;
    }


    printf("found!!!!!!!!!!!!!!!!!\n");

    forward_packet_send(packet, handle);
    backward_packet_send(packet, handle);

}


int main(int argc, char*argv[]){
        if (argc != 3) {
        usage();
        return -1;
    }

    pattern = argv[2];
    dev = argv[1];

    char* dev = argv[1];
    char* pattern= argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    //printf("%s", pattern);


    getMyMac(dev, my_mac);
    // printf("%02x", my_mac[0]);
    // printf("%02x", my_mac[1]);
    // printf("%02x", my_mac[2]);
    // printf("%02x", my_mac[3]);
    // printf("%02x", my_mac[4]);
    // printf("%02x", my_mac[5]);


    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

     while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        block_packet(packet, handle);
    }
   pcap_close(handle);

}

