#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <pcap.h>
#include <dnet.h>
#include "prtlog.h"
#include "proxy.h"

#define CMD "tcp and dst host %s and src host %s"

struct addr vad, vha;        // victim ip and mac address structures
struct addr aad, aha;        // attacker ip and mac address structures
struct addr rvad, rvha;      // victim replay ip and mac address structures
struct addr raad,raha;	     // attacker replay ip and mac address structures

char vip[32], vhw[32];       // victim ascii ip and mac addresses
char aip[32], ahw[32];       // attacker ascii ip and mac addresses
char rvip[32], rvhw[32];     // victim replay ascii ip and mac addresses
char raip[32], rahw[32];     // attacker replay ascii ip and mac addresses
char dumpname[32];
char iface[32];
char timing[32];
char ebuf[2048];

int err;
uint16_t vp, ap, rvp, rap;
uint32_t localnet, netmask;
uint32_t g_seq, g_ack, temp;

intf_t *i;
eth_t *e;
pcap_t *p;
struct intf_entry ie;
struct bpf_program fcode;
struct eth_hdr *ethheader;
struct ip_hdr *ipheader;
struct tcp_hdr *tcpheader;

int main(int argc, char **argv) {
	struct pcap_file_header fhdr;
	struct my_pkthdr phdr, hdr;
	struct eth_hdr *ehdr;
	struct arp_hdr *arphdr;
	struct ip_hdr *iphdr;
	struct tcp_hdr *tcphdr;
	struct udp_hdr *udphdr;
	struct icmp_hdr *icmphdr;
	struct addr ad;
	char buf[4096];
	char *ptr;
	int fd, n, s, pnum = 0, firsttime = 1, otherfirsttime = 1, b_usec, c_usec, sendflag = 0;
	unsigned int b_sec, c_sec;

	// check for errors

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <configuration file>\n", argv[0]);
		exit(-1);
	}

	readcfg(argv[1]);
	open_devices();
	setfilter();

	if((fd = open(dumpname, O_RDONLY)) == -1) {
		perror(dumpname);
		exit(-1);
	}

	// read and print info in the file header

	if (read(fd, &fhdr, sizeof(struct pcap_file_header)) == -1) {
		perror(argv[1]);
		close(fd);
		exit(-1);
	}

	if (fhdr.magic == PCAP_MAGIC)
		printf("PCAP_MAGIC\n");
	else
		printf("Why isn't this PCAP_MAGIC?\n");	
	printf("Version major number = %u\n", fhdr.version_major);
	printf("Version minor number = %u\n", fhdr.version_minor);
	printf("GMT to local correction = %u\n", fhdr.thiszone);
	printf("Timestamp accuracy = %u\n", fhdr.sigfigs);
	printf("Snaplen = %u\n", fhdr.snaplen);
	printf("Linktype = %u\n\n", fhdr.linktype);

	// read each packet one at a time

	while((n = read(fd, &phdr, sizeof(struct my_pkthdr))) == sizeof(struct my_pkthdr)) {
		printf("Packet %d\n", pnum++);

		// get the time relative to the first packet

		if (firsttime) {
			firsttime = 0;
			b_sec = phdr.ts.tv_sec;
			b_usec = phdr.ts.tv_usec;
		}
		c_sec = (unsigned)phdr.ts.tv_sec - b_sec;
		c_usec = (unsigned)phdr.ts.tv_usec - b_usec;
		while (c_usec < 0) {
			c_usec += 1000000;
			c_sec--;
		}

		// print packet header info

		printf("%05u.%06u\n", (unsigned)c_sec, (unsigned)c_usec);
		printf("Captured Packet Length = %u\n", phdr.caplen);
		printf("Actual Packet Length = %u\n", phdr.len);
		printf("Ethernet Header\n");
		if (read(fd, buf, phdr.len) != phdr.len) {
			perror(argv[1]);
			close(fd);
			exit(-1);
		}

		// get ethernet header info

		ehdr = (struct eth_hdr *)buf;
		addr_pack(&ad,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(ehdr->eth_src),ETH_ADDR_LEN);
		printf("\teth_src = %s\n", addr_ntoa(&ad));
		if (addr_cmp(&ad, &vha) == 0) 
			printf("\treplay_src = %s\n", addr_ntoa(&rvha));
		else
			printf("\treplay_src = %s\n", addr_ntoa(&raha));

		addr_pack(&ad,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(ehdr->eth_dst),ETH_ADDR_LEN);
		printf("\teth_dst = %s\n", addr_ntoa(&ad));
		if (addr_cmp(&ad, &vha) == 0) 
			printf("\treplay_src = %s\n", addr_ntoa(&rvha));
		else
			printf("\treplay_src = %s\n", addr_ntoa(&raha));

		// if ethernet type is IP or ARP, print info in the next header

		if (ntohs(ehdr->eth_type) == ETH_TYPE_ARP) {
			printf("\tARP\n");
			arphdr = (struct arp_hdr *)(buf + sizeof(struct eth_hdr));
			printf("\t\tarp operation = ");
			if (ntohs(arphdr->ar_op) == ARP_OP_REQUEST)
				printf("Arp Request\n");
			if (ntohs(arphdr->ar_op) == ARP_OP_REPLY)
				printf("Arp Reply\n");
			if (ntohs(arphdr->ar_op) == ARP_OP_REVREQUEST)
				printf("Arp Reverse Request\n");
			if (ntohs(arphdr->ar_op) == ARP_OP_REVREPLY)
				printf("Arp Reverse Reply\n");
		} else if (ntohs(ehdr->eth_type) == ETH_TYPE_IP) {
			printf("\tIP\n");
			iphdr = (struct ip_hdr *)(buf + sizeof(struct eth_hdr));
			printf("\t\tip len = %d\n", ntohs(iphdr->ip_len));
			addr_pack(&ad,ADDR_TYPE_IP,IP_ADDR_BITS,&(iphdr->ip_src),IP_ADDR_LEN);
			printf("\t\tip src = %s\n", addr_ntoa(&ad));
			if (addr_cmp(&ad, &vad) == 0) 
				printf("\t\treplay src = %s\n", addr_ntoa(&rvad));
			else {
				printf("\t\treplay src = %s\n", addr_ntoa(&raad));
				memcpy(&ehdr->eth_src, &raha.addr_eth, ETH_ADDR_LEN);
				memcpy(&iphdr->ip_src, &raad.addr_ip, IP_ADDR_LEN);
			}
			addr_pack(&ad,ADDR_TYPE_IP,IP_ADDR_BITS,&(iphdr->ip_dst),IP_ADDR_LEN);
			printf("\t\tip dst = %s\n", addr_ntoa(&ad));
			if (addr_cmp(&ad, &vad) == 0){ 
				printf("\t\treplay dst = %s\n", addr_ntoa(&rvad));
				memcpy(&ehdr->eth_dst, &rvha.addr_eth, ETH_ADDR_LEN);
				memcpy(&iphdr->ip_dst, &rvad.addr_ip, IP_ADDR_LEN);
				sendflag = 1;
			}
			else
				printf("\t\treplay dst = %s\n", addr_ntoa(&raad));
			if (iphdr->ip_p == IP_PROTO_ICMP){
				printf("\t\tICMP\n");
				icmphdr = (struct icmp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				if (icmphdr->icmp_type == ICMP_ECHOREPLY)
					printf("\t\t\tEcho Reply\n");
				else if (icmphdr->icmp_type == ICMP_UNREACH)
					printf("\t\t\tDestination Unreachable\n");
				else if (icmphdr->icmp_type == ICMP_SRCQUENCH)
					printf("\t\t\tSource Quench\n");
				else if (icmphdr->icmp_type == ICMP_REDIRECT)
					printf("\t\t\tRoute Redirection\n");
				else if (icmphdr->icmp_type == ICMP_ALTHOSTADDR)
					printf("\t\t\tAlternate Host Address\n");
				else if (icmphdr->icmp_type == ICMP_ECHO)
					printf("\t\t\tEcho\n");
				else if (icmphdr->icmp_type == ICMP_RTRADVERT)
					printf("\t\t\tRoute Advertisement\n");
				else if (icmphdr->icmp_type == ICMP_RTRSOLICIT)
					printf("\t\t\tRoute Solicitation\n");
				else if (icmphdr->icmp_type == ICMP_TIMEXCEED)
					printf("\t\t\tTime Exceeded\n");
				else if (icmphdr->icmp_type == ICMP_PARAMPROB)
					printf("\t\t\tBad IP Header\n");
				else if (icmphdr->icmp_type == ICMP_TSTAMP)
					printf("\t\t\tTime Stamp Request\n");
				else if (icmphdr->icmp_type == ICMP_TSTAMPREPLY)
					printf("\t\t\tTime Stamp Reply\n");
				else if (icmphdr->icmp_type == ICMP_INFO)
					printf("\t\t\tInformation Request\n");
				else if (icmphdr->icmp_type == ICMP_INFOREPLY)
					printf("\t\t\tInformation Reply\n");
				else if (icmphdr->icmp_type == ICMP_MASK)
					printf("\t\t\tAddress Mask Request\n");
				else if (icmphdr->icmp_type == ICMP_MASKREPLY)
					printf("\t\t\tAddress Mask Reply\n");
				else if (icmphdr->icmp_type == ICMP_TRACEROUTE)
					printf("\t\t\tTraceroute\n");
				else if (icmphdr->icmp_type == ICMP_DATACONVERR)
					printf("\t\t\tData Conversion Error\n");
				else if (icmphdr->icmp_type == ICMP_MOBILE_REDIRECT)
					printf("\t\t\tMobile Host Redirection\n");
				else if (icmphdr->icmp_type == ICMP_IPV6_WHEREAREYOU)
					printf("\t\t\tIPv6 Where are you?\n");
				else if (icmphdr->icmp_type == ICMP_IPV6_IAMHERE)
					printf("\t\t\tIPv6 I am here.\n");
				else if (icmphdr->icmp_type == ICMP_MOBILE_REG)
					printf("\t\t\tMobile Registration Request\n");
				else if (icmphdr->icmp_type == ICMP_MOBILE_REGREPLY)
					printf("\t\t\tMobile Registration Reply\n");
				else if (icmphdr->icmp_type == ICMP_DNS)
					printf("\t\t\tDomain Name Request\n");
				else if (icmphdr->icmp_type == ICMP_DNSREPLY)
					printf("\t\t\tDomain Name Reply\n");
				else if (icmphdr->icmp_type == ICMP_SKIP)
					printf("\t\t\tSkip\n");
				else if (icmphdr->icmp_type == ICMP_PHOTURIS)
					printf("\t\t\tPhoturis\n");
				else
					printf("\t\t\tUnknown\n");
			}	
			else if (iphdr->ip_p == IP_PROTO_IGMP){
				printf("\t\tIGMP\n");
			}
			else if (iphdr->ip_p == IP_PROTO_TCP){
				printf("\t\tTCP\n");
				tcphdr = (struct tcp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				printf("\t\t\tSrc Port = %d\n", ntohs(tcphdr->th_sport));
				printf("\t\t\tDst Port = %d\n", ntohs(tcphdr->th_dport));
				printf("\t\t\tSeq = %ld\n", ntohl(tcphdr->th_seq));
				printf("\t\t\tAck = %ld\n", ntohl(tcphdr->th_ack));
				if (sendflag == 1 && otherfirsttime == 1) {
					otherfirsttime = 0;
					tcphdr->th_sport = htons(rap);
					tcphdr->th_dport = htons(rvp);
					ip_checksum((void *)iphdr, ntohs(iphdr->ip_len));
					s = eth_send(e, buf, phdr.len);
					if (s == -1) {
						perror("send failure");
						exit(-1);
					} else if (s != phdr.len) {
						fprintf(stderr,"Partial packet transmission%d/%d\n", s, phdr.len);
					}
				       	sendflag = 0;
				} else if (sendflag == 1) {
					tcphdr->th_sport = htons(rap);
					tcphdr->th_dport = htons(rvp);
					temp = ntohl(g_seq);
					temp++;
					g_seq = htonl(temp);
					tcphdr->th_seq = g_ack;
					tcphdr->th_ack = g_seq;
					ip_checksum((void *)iphdr, ntohs(iphdr->ip_len));
					s = eth_send(e, buf, phdr.len);
					if (s == -1) {
						perror("send failure");
						exit(-1);
					} else if (s != phdr.len) {
						fprintf(stderr,"Partial packet transmission%d/%d\n", s, phdr.len);
					}
				       	sendflag = 0;
				} else {
					while ( (ptr = (char *) pcap_next(p, &hdr)) == NULL)
						;
					ethheader = (struct eth_hdr *)ptr;
					ipheader = (struct ip_hdr *) (ptr + ETH_HDR_LEN);
					tcpheader = (struct tcp_hdr *) (ptr + ETH_HDR_LEN + IP_HDR_LEN);
					g_seq = tcpheader->th_seq;
					g_ack = tcpheader->th_ack;
				}
			}
			else if (iphdr->ip_p == IP_PROTO_UDP){
				printf("\t\tUDP\n");
				udphdr = (struct udp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				printf("\t\t\tSrc Port = %d\n", ntohs(udphdr->uh_sport));
				printf("\t\t\tDst Port = %d\n", ntohs(udphdr->uh_dport));
			}
			else
				printf("\t\tOTHER\n");
		} 

		// print the ethernet type but skip the rest of the packet if it's not IP or ARP

		else if (ntohs(ehdr->eth_type) == ETH_TYPE_PUP) {
			printf("\tPUP\n");
		} else if (ntohs(ehdr->eth_type) == ETH_TYPE_REVARP) {
                        printf("\tReverse ARP\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_8021Q) {
                        printf("\t8021Q\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_IPV6) {
                        printf("\tIPV6\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_MPLS) {
                        printf("\tMPLS\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_MPLS) {
                        printf("\tMPLS Multicast\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_PPPOEDISC) {
                        printf("\tPPP Over Ethernet Discovery Stage\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_PPPOE) {
                        printf("\tPPP Over Ethernet Session Stage\n");
                } else if (ntohs(ehdr->eth_type) == ETH_TYPE_LOOPBACK) {
                        printf("\tLoopback\n");
                } else
			printf("\tOTHER\n");
		printf("\n");
	}

	// check if there was an error reading the packet headers

	if (n < 0) {
		perror(argv[1]);
		close(fd);
		exit(-1);
	}

	close(fd);
	return 0;
}

void readcfg(char *filename) {
  FILE *fp;

  fp = fopen(filename,"r");
  if ( fp == NULL ) {
    perror(filename);
    exit(-1);
  }

  if ( fgets(dumpname, sizeof(dumpname), fp) == NULL) {
	  perror("dump name");
	  exit(-1);
  }
  rmnl(dumpname);

  /* Get victim addresses */
  if ( (err = load_address(fp,vip,vhw,&vad,&vha)) < 0 )
    load_error(err,"Victim");
  fscanf(fp, "%d ", &vp);

  /* Get attacker addresses */
  if ( (err = load_address(fp,aip,ahw,&aad,&aha)) < 0 )
    load_error(err,"Attacker");
  fscanf(fp, "%d ", &ap);
  
  if ( (err = load_address(fp,rvip,rvhw,&rvad,&rvha)) < 0 )
    load_error(err,"Replay Victim");
  fscanf(fp, "%d ", &rvp);
  
  if ( (err = load_address(fp,raip,rahw,&raad,&raha)) < 0 )
    load_error(err,"Replay Attacker");
  fscanf(fp, "%d ", &rap);

  if ( fgets(iface, sizeof(iface), fp) == NULL ) {
    fprintf(stderr, "Interface too large\n");
    exit(-1);
  }
  rmnl(iface);

  if ( fgets(timing, sizeof(timing), fp) == NULL ) {
    fprintf(stderr, "Timing too large\n");
    exit(-1);
  }
  rmnl(timing);
  fclose(fp);
}

int load_address(FILE *fp, char *ip, char *hw,struct addr *ad, struct addr *ha) {
  /* Get ip address */
  if ( fgets(ip, 32, fp) == NULL ) 
    return(-1);
  rmnl(ip);
  if ( addr_aton(ip, ad) == -1 ) 
    return(-2);
  /* Get hardware address */
  if ( fgets(hw, 32, fp) == NULL ) 
    return(-3);
  rmnl(hw);
  if ( addr_aton(hw, ha) == -1 ) {
    return(-4);
  }
  return(0);
}


void rmnl(char *s) {
  while ( *s != '\n' && *s != '\0' )
    s++;
  *s = '\0';
}

void load_error(int e, char *mach) {
  if ( e == -1 )
    fprintf(stderr, "%s ip too large\n", mach);
  else if ( e == -2 )
    fprintf(stderr, "%s ip incorrectly formatted\n", mach);
  else if ( e == -3 )
    fprintf(stderr, "%s mac address too large\n", mach);
  else if ( e == -4 )
    fprintf(stderr, "%s mac address incorrectly formatted\n", mach);
  else
    fprintf(stderr, "Unknown error %d for %s\n", e, mach);
  exit(-1);
}

void open_devices(void) {

    i = intf_open();
    if ( i == NULL ) {
      perror("intf open error");
      exit(-1);
    }
    strncpy(ie.intf_name, iface, 60);
    if ( intf_get(i, &ie) == -1 ) {
      perror("intf get error");
      exit(-1);
    }
  
    e = eth_open(iface);
    if ( e == NULL ) {
      perror("eth open error");
      exit(-1);
    }
    p = pcap_open_live(iface, 65535, 1, 1000, ebuf);
    if (p == NULL) {
      perror(ebuf);
      exit(-1);
    }
}

void setfilter() {
  char cmd[128];
  if ( pcap_lookupnet(iface, &localnet, &netmask, ebuf) < 0 ) {
    fprintf(stderr,"pcap_lookupnet: %s\n", ebuf);
    exit(-1);
  }
  snprintf(cmd, sizeof(cmd), CMD, raip, rvip);
  printf("Filter:%s\n",cmd);
  if ( pcap_compile(p, &fcode, cmd, 0, netmask) < 0 ) {
    fprintf(stderr,"pcap_compile: %s\n", pcap_geterr(p));
    exit(-1);
  }
  if ( pcap_setfilter(p, &fcode) < 0 ) {
    fprintf(stderr,"pcap_setfilter: %s\n", pcap_geterr(p));
    exit(-1);
  }
}
