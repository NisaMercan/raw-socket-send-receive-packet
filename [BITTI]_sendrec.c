/*** Send Packet Using Raw Socket sendrec5.c
#  *
#  * 09.09.2020 Nisa Mercan <nisamercan11@gmail.com>
#  * 10.09.2020 09:24 updated
#  * gcc sendrec5.c -o sendraw03 , sudo ./sendraw01 enp0s3 , sudo tcpdump -nettti enp0s3 '(ether dst host 00:11:22:33:44:55)'
#  *
#  ***/

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/udp.h>

#define DEFAULT_IFNAME	"enp0s3"  /* If there is no interface this will be used as default. */
#define BUFFER_SIZ  1024        

unsigned short check_sum(unsigned short* buf, int nbytes);

int main(int argc, char* argv[]) {
	int i, sockfd;
	ssize_t recbytes;
	int data_len = 0;
	char ifName[IFNAMSIZ];
	char data[BUFFER_SIZ];

	/* Get information about the network such as ip address, interface index, name, mask and mtu*/
	struct ifreq if_index;  /* Get the index of the interface */
	struct ifreq if_mac;  /*  MAC address of the interface  */
	struct ifreq if_ip;   /*   IP address of the interface  */

	struct ether_header* eh = (struct ether_header*)data;  /* the ethernet header */
	struct iphdr* iph = (struct iphdr*)(data + sizeof(struct ether_header));   /* the ip header */
	struct udphdr* udph = (struct udphdr*)(data + sizeof(struct iphdr) + sizeof(struct ether_header)); /* the udp header */

	struct sockaddr_ll socket_address; /* link level destination address */

	/* UPDATE */ struct ifreq ifprom; /* to set promiscuous mode */
	struct sockaddr_storage src_addr; /* to get the source IP sin_addr */
	char src[INET6_ADDRSTRLEN];       /* src is the source that we received data from INET6_ADDRSTRLEN 46 */


	/* Get the interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IFNAME); /* If there is no given interface, use the default one */


	/* Open RAW socket to send on */
	/* socket(int socket_family, int socket_type, int protocol) */
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));  /* UPDATE */
	if (sockfd == -1)
		perror("socket");


	strncpy(if_index.ifr_name, ifName, IFNAMSIZ - 1);
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
	strncpy(if_ip.ifr_name, ifName, IFNAMSIZ - 1);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_index) < 0) /* the index number of a network interface can be obtained using the ioctl command SIOCGIFINDEX*/
		printf("SIOCGIFINDEX: Error.");
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) /*the MAC address of an interface can be obtained using the ioctl command SIOCGIFHWADDR */
		printf("SIOCGIFHWADDR: Error.");
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)  /*the IP address of an interface can be obtained using the ioctl command SIOCGIFHWADDR */
		printf("SIOCGIFADDR: Error.");


	/* Data to send */
	memset(data, 0, BUFFER_SIZ);
	data_len += sizeof(struct ether_header);
	data_len += sizeof(struct iphdr);
	data_len += sizeof(struct udphdr);
	data[data_len++] = 0xde;
	data[data_len++] = 0xad;
	data[data_len++] = 0xbe;
	data[data_len++] = 0xef;

	/* Fill the socket_address */
	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_ifindex = if_index.ifr_ifindex; /* Interface index */
	socket_address.sll_halen = ETH_ALEN; /* Length of address */
	socket_address.sll_family = AF_PACKET; /* packet family */
	socket_address.sll_protocol = htons(ETH_P_ALL); /* protocol */
	socket_address.sll_addr[0] = 0x00; /* Destination MAC */
	socket_address.sll_addr[1] = 0x11;
	socket_address.sll_addr[2] = 0x22;
	socket_address.sll_addr[3] = 0x33;
	socket_address.sll_addr[4] = 0x44;
	socket_address.sll_addr[5] = 0x55;

	/* Fill the Ethernet header */
	eh->ether_dhost[0] = 0x00; /* Set MAC destination */
	eh->ether_dhost[1] = 0x11;
	eh->ether_dhost[2] = 0x22;
	eh->ether_dhost[3] = 0x33;
	eh->ether_dhost[4] = 0x44;
	eh->ether_dhost[5] = 0x55;
	eh->ether_shost[0] = ((uint8_t*)&if_mac.ifr_hwaddr.sa_data)[0]; /* Set MAC source */ /* extract the hardware address ifr_hwaddr.sa_data */
	eh->ether_shost[1] = ((uint8_t*)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t*)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t*)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t*)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t*)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_type = htons(ETH_P_IP);  /* htons(uint16_t hostshort) converts the unsigned short int from host byte order to network byte order. ETH_P_IP receive all IP packets*/


	/* Fill the IP header */
	iph->saddr = inet_addr(inet_ntoa(((struct sockaddr_in*)&if_ip.ifr_addr)->sin_addr)); /* IP source address. inet_addr converts an IPv4 address from a string in dotted decimal to an integer. sockaddr_in IP socket address sin_addr the IP address in the socket */
	iph->daddr = inet_addr("192.168.0.111"); /* destination address */
	iph->ihl = 5;							/* length */
	iph->version = 4;						 /* ip */
	iph->tos = 16;							/* type of service 16 is immediate*/
	iph->id = htons(54321);					 /* identification (ID) 16-bit value*/
	iph->ttl = 64;							 /* time to live  initial value 64 but max 255 */
	iph->protocol = 17;						 /* UDP */
	iph->tot_len = htons(data_len - sizeof(struct ether_header)); /* total length */
	iph->check = check_sum((unsigned short*)(data + sizeof(struct ether_header)), sizeof(struct iphdr) / 2); /* Get the IP checksum on the full header */


	/* Fill the UDP Header */
	udph->source = htons(3423);
	udph->dest = htons(5342);
	udph->len = htons(data_len - sizeof(struct ether_header) - sizeof(struct iphdr));

	/* Send packet */
	/* ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);*/
	sendto(sockfd, data, data_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
	if (sendto(sockfd, data, data_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	/* UPDATE */  ifprom.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifprom);

	/* Set socket option and bind to an device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ - 1) == -1)  /* To bind the socket to a device specified in the passed interface name */
		perror("SO_BINDTODEVICE");


	while (1) {
		recbytes = recvfrom(sockfd, data, BUFFER_SIZ, 0, NULL, NULL); /* receive data from socket */
		printf("\n\n\n\nReceived packet bytes is : %lu\n", recbytes);
		printf("Received packet protocol : % d\n", eh->ether_type);  //eh->h_proto

		/* Get the incoming packet's destination address and check if it is match with destination address */
		if (eh->ether_dhost[0] == 0x08 && eh->ether_dhost[1] == 0x00 && eh->ether_dhost[2] == 0x27 && eh->ether_dhost[3] == 0x26 && eh->ether_dhost[4] == 0x2a && eh->ether_dhost[5] == 0x94)
			printf("Packet destination address is matched. Packet MAC address: %x:%x:%x:%x:%x:%x\n\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
		else
			printf("Packet destination address is unmatched. Packet destination MAC: %x:%x:%x:%x:%x:%x\n\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);

		/* Get source IP */
		((struct sockaddr_in*)&src_addr)->sin_addr.s_addr = iph->saddr;
		inet_ntop(AF_INET, &((struct sockaddr_in*)&src_addr)->sin_addr, src, sizeof src);
		printf("Source IP: %s\nMy IP: %s\n", src, inet_ntoa(((struct sockaddr_in*)&if_ip.ifr_addr)->sin_addr));

		//
		printf("\t IP Infos:\n");
		printf("\t  Version: %d\n", (unsigned int)iph->version);
		printf("\t  Internet Header Length: %d DWORDS or % d bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
		printf("\t  Type Of Service: %d\n", (unsigned int)iph->tos);
		printf("\t  Total Length: %d bytes\n", ntohs(iph->tot_len));
		printf("\t  Identification: %d\n", ntohs(iph->id));
		printf("\t  Time To Live: %d\n", (unsigned int)iph->ttl);
		printf("\t  Protocol: %d\n", (unsigned int)iph->protocol);
		printf("\t  Header Checksum: %d\n", ntohs(iph->check));
		printf("\t UDP Infos:\n");
		printf("\t  Source Port: %d\n", ntohs(udph->source));
		printf("\t  Destination Port: %d\n", ntohs(udph->dest));
		printf("\t  UDP Length: %d\n", ntohs(udph->len));
		printf("\t  UDP Checksum: %d\n\n", ntohs(udph->check));

		/* Print packet */
		printf("\tReceived Data:");
		for (i = 0; i < recbytes; i++) printf("%02x:", data[i]);
		printf("\n");
	}
	return 0;
}

unsigned short check_sum(unsigned short* buf, int nbytes) {
	unsigned long sum;
	for (sum = 0; nbytes > 0; nbytes--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}
