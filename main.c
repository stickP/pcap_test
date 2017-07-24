
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#define SIZE_ETHERNET 14

/*
struct pcap_pkthdr{
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};
*/

struct ether_hdr{
    struct ether_addr dmac, smac;
    u_int16_t ether_type;
};

struct ip_hdr{
    u_int8_t ip_vhl;
    u_int8_t ip_tos;
    u_int16_t ip_tlen;
    u_int16_t ip_id;
    u_int16_t ip_offset;
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int16_t ip_check;
    struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) ((ip->ip_vhl) & 0x0f)

struct tcp_hdr{
    u_int16_t tcp_srcp;
    u_int16_t tcp_dstp;
    u_int32_t tcp_seqnum;
    u_int32_t tcp_acknum;
    u_int8_t tcp_offset_rsvd;
    u_int8_t tcp_flags;
    u_int16_t tcp_win;
    u_int16_t tcp_check;
    u_int16_t tcp_urgp;
};

#define TCP_OFF(tcp) (((tcp->tcp_offset_rsvd) & 0xf0) >> 4)

int main(int argc, char *argv[]){

    int cnt;
    char *dev;
    char buf[20];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    //bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_int8_t *packet;
    const u_int8_t *res;

    const struct ether_hdr *ethernet;
    const struct ip_hdr *ip;
    const struct tcp_hdr *tcp;
    const char *payload;

    u_int32_t size_payload;
    u_int32_t size_ip;
    u_int32_t size_tcp;

    //pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf);
    //int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
    //int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
    //int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    //void got_packet(u_char *args, cont struct pcap_pkthdr, *header, const u_char *packet)

    /*
    dev = pcap_lookupdev(errbuf);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    */

    dev = argv[1];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev ,errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    cnt = 0;

    while((res = pcap_next_ex(handle, &header, &packet) >= 0)){

        cnt++;
        if(cnt > 30)
            break;

        if (res == 0)
            continue;

        ethernet = (struct ehter_hdr*)(packet);

        ip = (struct ip_hdr*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

        if (size_ip < 16){
            printf("Invalid IP header length : %u bytes\n", size_ip);
            continue;
        }

        tcp = (struct tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TCP_OFF(tcp)*4;
        if (size_tcp < 20){
            printf("Invalid TCP header length : %u bytes\n", size_tcp);
            continue;
        }

        printf("-------------------------------------------------\n");
        printf("Sorce Mac Address:                %s\n", ether_ntoa(&ethernet->smac));
        printf("Destination Mac Address:          %s\n", ether_ntoa(&ethernet->dmac));
        printf("-------------------------------------------------\n");
        inet_ntop(AF_INET, &(ip->ip_src), buf, sizeof(buf));
        printf("Sorce IP Address:                 %s\n", buf);
        inet_ntop(AF_INET, &(ip->ip_dst), buf, sizeof(buf));
        printf("Destination IP Address:           %s\n", buf);
        printf("-------------------------------------------------\n");
        printf("Sorce Port:                       %d\n", ntohs(tcp->tcp_srcp));
        printf("Destination Port:                 %d\n", ntohs(tcp->tcp_dstp));
        printf("-------------------------------------------------\n");

        size_payload = ntohs(ip->ip_tlen) - (size_ip + size_tcp);

        if (size_payload > 0){
            payload = (char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            printf("Data:\n%s\n", payload);
        }
        else
            printf("No Data\n");
        printf("-------------------------------------------------\n");

    }

    if(res == -1){
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);

    return 0;
}
