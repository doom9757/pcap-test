#include <pcap.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//#pragma comment (lib, "wpcap.lib")
//#pragma comment (lib, "ws2_32.lib" )

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
//#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
//#endif
//#if (LIBNET_BIG_ENDIAN)
//    u_int8_t th_off:4,        /* data offset */
//           th_x2:4;         /* (unused) */
//#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


struct ether_addr
{
        unsigned char ether_addr_octet[6];
};

struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};

void print_ether_header(const unsigned char *data)
{
        struct  ether_header *eh;
        unsigned short ether_type;
        eh = (struct ether_header *)data;    
        ether_type=ntohs(eh->ether_type);   
        if (ether_type!=0x0800)
        {
                printf("ether type wrong\n");
                return ;
        }
        printf("\n============ETHERNET HEADER==========\n");
        printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                    eh->ether_dhost.ether_addr_octet[0],
                    eh->ether_dhost.ether_addr_octet[1],
                    eh->ether_dhost.ether_addr_octet[2],
                    eh->ether_dhost.ether_addr_octet[3],
                    eh->ether_dhost.ether_addr_octet[4],
                    eh->ether_dhost.ether_addr_octet[5]);
        printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                    eh->ether_shost.ether_addr_octet[0],
                    eh->ether_shost.ether_addr_octet[1],
                    eh->ether_shost.ether_addr_octet[2],
                    eh->ether_shost.ether_addr_octet[3],
                    eh->ether_shost.ether_addr_octet[4],
                    eh->ether_shost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char *data){
	struct ip *IP;
	IP = (struct ip *)(data);
	printf("ip header\n");
	printf("src addr : %s\n", inet_ntoa(IP->ip_src));
	printf("des addr : %s\n", inet_ntoa(IP->ip_dst));
	return (IP->ip_len);
}

int print_tcp_header(const unsigned char *data){
	//struct tcphdr *TCP;
	struct libnet_tcp_hdr *TCP;
	TCP = (struct libnet_tcp_hdr *)(data);
	printf("tcp header\n");
	printf("src port : %d\n",ntohs(TCP->th_sport));
	printf("des port : %d\n",ntohs(TCP->th_dport));
	return (TCP->th_off)*4;
}

void print_data(const unsigned char *data){
	for(int i=0 ;i<16;i++){
		printf("%02x ",*(data+i));	
	}
}
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
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
	print_ether_header(packet);
        packet = packet + 14;
	int num = print_ip_header(packet);
	packet = packet + num;
	int num2 = print_tcp_header(packet);
	packet = packet + num2;
	print_data(packet);
        printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(handle);
    return 0;
}
