/*
 * Send an IPv6 packet via raw socket at the link layer (ethernet frame).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>			 // struct addrinfo
#include <sys/types.h>		 // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>		 // needed for socket()
#include <netinet/in.h>		 // IPPROTO_TCP, INET6_ADDRSTRLEN
#include <netinet/ip.h>		 // IP_MAXPACKET(which is 65535)
#include <netinet/ip6.h>	 // struct ip6_hdr
#include <netinet/tcp.h>	 // struct tcphdr
#include <arpa/inet.h>		 // inet_pton() and inet_ntop()
#include <sys/ioctl.h>		 // macro ioctl is defined
#include <bits/ioctls.h>	 // defines values for argument "request" of ioctl.
#include <net/if.h>			 // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll(see man 7 packet)
#include <net/ethernet.h>
#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data
#define BUFFSIZE 1518 //

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum(uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1)
	{
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0)
	{
		sum += *(uint8_t *)addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

// Build IPv6 TCP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
tcp6_checksum(struct ip6_hdr iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{
	uint32_t lvalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int i, chksumlen = 0;

	ptr = &buf[0]; // ptr points to beginning of buffer buf

	// Copy source IP address into buf (128 bits)
	memcpy(ptr, &iphdr.ip6_src, sizeof(iphdr.ip6_src));
	ptr += sizeof(iphdr.ip6_src);
	chksumlen += sizeof(iphdr.ip6_src);

	// Copy destination IP address into buf (128 bits)
	memcpy(ptr, &iphdr.ip6_dst, sizeof(iphdr.ip6_dst));
	ptr += sizeof(iphdr.ip6_dst);
	chksumlen += sizeof(iphdr.ip6_dst);

	// Copy TCP length to buf (32 bits)
	lvalue = htonl(sizeof(tcphdr) + payloadlen);
	memcpy(ptr, &lvalue, sizeof(lvalue));
	ptr += sizeof(lvalue);
	chksumlen += sizeof(lvalue);

	// Copy zero field to buf (24 bits)
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 3;

	// Copy next header field to buf (8 bits)
	memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
	ptr += sizeof(iphdr.ip6_nxt);
	chksumlen += sizeof(iphdr.ip6_nxt);

	// Copy TCP source port to buf (16 bits)
	memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
	ptr += sizeof(tcphdr.th_sport);
	chksumlen += sizeof(tcphdr.th_sport);

	// Copy TCP destination port to buf (16 bits)
	memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
	ptr += sizeof(tcphdr.th_dport);
	chksumlen += sizeof(tcphdr.th_dport);

	// Copy sequence number to buf (32 bits)
	memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
	ptr += sizeof(tcphdr.th_seq);
	chksumlen += sizeof(tcphdr.th_seq);

	// Copy acknowledgement number to buf (32 bits)
	memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
	ptr += sizeof(tcphdr.th_ack);
	chksumlen += sizeof(tcphdr.th_ack);

	// Copy data offset to buf (4 bits) and
	// copy reserved bits to buf (4 bits)
	cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
	memcpy(ptr, &cvalue, sizeof(cvalue));
	ptr += sizeof(cvalue);
	chksumlen += sizeof(cvalue);

	// Copy TCP flags to buf (8 bits)
	memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
	ptr += sizeof(tcphdr.th_flags);
	chksumlen += sizeof(tcphdr.th_flags);

	// Copy TCP window size to buf (16 bits)
	memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
	ptr += sizeof(tcphdr.th_win);
	chksumlen += sizeof(tcphdr.th_win);

	// Copy TCP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 2;

	// Copy urgent pointer to buf (16 bits)
	memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
	ptr += sizeof(tcphdr.th_urp);
	chksumlen += sizeof(tcphdr.th_urp);

	// Copy payload to buf
	memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i = 0; i < payloadlen % 2; i++, ptr++)
	{
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum((uint16_t *)buf, chksumlen);
}

int main(int argc, char **argv)
{
	int i, status, frame_length, sd, bytes, tcp_flags[8];
	uint8_t src_mac[6], dst_mac[6], ether_frame[1518];
	char buff1[BUFFSIZE], interface[40], src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	struct ip6_hdr iphdr;
	struct tcphdr tcphdr;
	struct addrinfo hints, *res;
	struct sockaddr_in6 *ipv6;
	struct sockaddr_ll device;
	struct ifreq ifr;
	void *tmp;

	char *payload;
	int payloadlen = 0;

	int portaIni;
	int portaFim;
	int op;

	// Args
	if (argc > 5)
	{
		strcpy(interface, argv[1]); // Interface
		strcpy(src_ip, argv[2]);	// IPv6 origem
		strcpy(dst_ip, argv[3]);	// IPv6 destino
		op = atoi(argv[4]);			// Operação
		portaIni = atoi(argv[5]);   // porta Ini
		portaFim = atoi(argv[6]);   // porta Fim

		printf("	***	TF Lab Redes ***\n");
		printf("Interface: %s\n", interface);
		printf("IP Origem: %s\n", src_ip);
		printf("IP Destino: %s\n", dst_ip);
		// printf("Operação: %d\n", op);
		// printf("Porta ini: %d\n", portaIni);
		// printf("Porta fim: %d\n", portaFim);
	}
	else
	{
		printf("Usage ipvc6_ll interface ipSource ipDestination op startPort endPort\n");
		printf(" op: \n");
		printf("   -1 - TCP connect \n");
		printf("   -2 - TCP hasl-opening \n");
		printf("   -3 - Stealth scan ou TCP FIN \n");
		printf("   -4 - SYN/ACK \n");
		return 0;
	}

	// Submit request for a socket descriptor to look up interface.
	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket() failed to get socket descriptor for using ioctl() ");
		exit(EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its MAC address.
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sd, SIOCSIFFLAGS, &ifr);

	// Copy source MAC address.
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset(&device, 0, sizeof(device));
	if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
	{
		perror("if_nametoindex() failed to obtain interface index ");
		exit(EXIT_FAILURE);
	}

	// Set destination MAC address: you need to fill these out
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	// Source IPv6 address: you need to fill this out
	//strcpy(src_ip, "2001:1bcd:123:1:20a:f7ff:fe2b:6942");

	// Fill out hints for getaddrinfo().
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo(dst_ip, NULL, &hints, &res)) != 0)
	{
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}
	ipv6 = (struct sockaddr_in6 *)res->ai_addr;
	tmp = &(ipv6->sin6_addr);
	if (inet_ntop(AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL)
	{
		status = errno;
		fprintf(stderr, "inet_ntop() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
	device.sll_halen = 6;

	// IPv6 header

	// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
	iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

	// Payload length (16 bits)
	iphdr.ip6_plen = htons(20);

	// Next header (8 bits): 6 for TCP****
	iphdr.ip6_nxt = 6; //IPPROTO_TCP;

	// Hop limit (8 bits): default to maximum value
	iphdr.ip6_hops = 255;

	// Source IPv6 address (128 bits)
	if ((status = inet_pton(AF_INET6, src_ip, &(iphdr.ip6_src))) != 1)
	{
		fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	// Destination IPv6 address (128 bits)
	if ((status = inet_pton(AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1)
	{
		fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	// TCP header
	/**
	 ** comecando trabajo AQUI!!!!
	**/
	tcphdr.th_sport = htons(1233);
	// tcphdr.th_dport = htons(1234); // parametro
	tcphdr.th_seq = 0;
	tcphdr.th_ack = 0;
	//tcphdr.th_flags = TH_SYN; // op
	tcphdr.th_win = htons(5840);
	tcphdr.th_off = 5;

	// **** OPERACAO ******
	switch (op)
	{
		case 1:
			printf("\n** Ataque TCP connect \n\n");
			tcphdr.th_flags = TH_SYN;
			break;

		case 2:
			printf("\n** Ataque TCP half-opening \n\n");
			tcphdr.th_flags = TH_SYN;
			break;

		case 3:
			printf("\n** Ataque Stealth scan ou TCP FIN \n\n");
			tcphdr.th_flags = TH_FIN;
			break;

		case 4:
			printf("\n** Ataque SYN/ACK \n\n");
			tcphdr.th_flags = TH_SYN | TH_ACK;
			break;

		default:
			printf("\n *** Operação não implementada !! \n\n");
			return (EXIT_FAILURE);
			break;
	}

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
	frame_length = ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN;

	// Destination and Source MAC addresses
	memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
	memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t)); //12 + 14

	// Next is ethernet type code (ETH_P_IPV6 for IPv6).
	// http://www.iana.org/assignments/ethernet-numbers
	ether_frame[12] = ETH_P_IPV6 / 256;
	ether_frame[13] = ETH_P_IPV6 % 256;

	// Next is ethernet frame data (IPv6 header + TCP header).

	// IPv6 header
	memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof(uint8_t)); //12+

	int port = portaIni;
	for (int port = portaIni; port <= portaFim; port++)
	{
		tcphdr.th_dport = htons(port);
		tcphdr.th_sum = tcp6_checksum(iphdr, tcphdr, (uint8_t *)0, 0);

		// TCP header
		memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

		// Send ethernet frame to socket.
		if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
		{
			perror("sendto() failed");
			exit(EXIT_FAILURE);
		}
	}



	//	***	recepcao de pacotes
	
	int packet_size = 0;
	char buff_ipv6[64];
	while (1)
	{
		packet_size = recv(sd, (char *)&buff1, sizeof(buff1), 0x0);
		
		struct iphdr *ip_packet = (struct iphdr *)(buff1 + ETH_HDRLEN);
		struct tcphdr *tcph = (struct tcphdr *)(buff1 + ETH_HDRLEN + IP6_HDRLEN);

		inet_ntop(AF_INET6, &(iphdr.ip6_dst), buff_ipv6, sizeof(buff_ipv6));

		if (buff1[67] == 0x12 && // IPv6
		!strcmp(dst_ip, buff_ipv6) // IP destino
		&& tcph->th_dport == tcphdr.th_sport) // Porta destino recebida = porta origem enviada
		{
			printf("Porta origem: %d\n", htons(tcph->th_sport));
			printf("Porta destino: %d\n", htons(tcph->th_dport));
			printf("Header: %d\n", tcph->th_off * 4);
			//printf("Payload: %d\n", htons(iph->ip_len)-20-tcph->th_off*4);
			printf("Flags: ACK %d SYN %d FIN %d\n", tcph->th_flags & 0x10, tcph->th_flags & 0x2, tcph->th_flags & 0x1);
			printf("Numero sequencia: %u\n", htonl(tcph->th_seq));
			printf("Numero confirmacao: %u\n", htonl(tcph->th_ack));
			
			if (op == 1 || op == 2) // TCP connect || TCP hasf-opening
			{
				if (tcph->th_flags == (TH_SYN | TH_ACK))
				{
					// *** send ACK as response
					tcph->th_dport = tcph->th_sport;
					
					if (op == 1)
					{
						// TCP connect
						tcphdr.th_flags = TH_ACK;
					}
					else 
					{
						// TCP hasf-opening
						tcphdr.th_flags = TH_RST;
					}

					tcphdr.th_sum = tcp6_checksum(iphdr, tcphdr, (uint8_t *)0, 0);
					memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

					// Send ethernet frame to socket.
					if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
					{
						perror("sendto() failed");
						exit(EXIT_FAILURE);
					}

					printf("Porta %d está aberta !\n", ntohs(tcph->th_sport));
				}
			}

			if (op == 3) // Stealth scan
			{
				printf("ok");
				if (!(tcph->th_flags & TH_RST) == TH_RST)
				{
					printf("Porta %d está fechada !\n", ntohs(tcph->th_sport));
				}
			}

			if (op == 4) // SYN/ACK
			{
				if (tcph->th_flags & TH_RST == TH_RST)
				{
					printf("Porta %d está aberta !\n", ntohs(tcph->th_sport));
				}
			}

		}
	}
	// Close socket descriptor.
	close(sd);

	return (EXIT_SUCCESS);
}
