///// https://www.onlinegdb.com/online_c_compiler (To test online)
//https://github.com/rbaron/raw_tcp_socket/blob/master/raw_tcp_socket.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include <unistd.h>          
#include <string.h>    

#include <netdb.h>            
#include <sys/types.h>        
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <netinet/ip6.h>      
#define __FAVOR_BSD           
#include <netinet/tcp.h>      
#include <arpa/inet.h>        
#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>           
#include <linux/if_ether.h>   
#include <linux/if_packet.h>  
#include <net/ethernet.h>

#include <errno.h>    
 

// Constants
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data

uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);




// Calcula o Checksum (RFC 1071)
uint16_t checksum(uint16_t *addr, int len)
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

// Constrói o IPv6 TCP pseudo-header e chama o checksum (Section 8.1 of RFC 2460).
uint16_t tcp6_checksum(struct ip6_hdr iphdr, struct tcphdr tcphdr)
{
	uint32_t lvalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int chksumlen = 0;

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
	lvalue = htonl(sizeof(tcphdr));
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

	return checksum((uint16_t *)buf, chksumlen);
}

void TCP_CONNECT(char *ip_origem, char *ip_destino, char *interface, int porta)
{

    // Variáveis
    int i, status, frame_length, sd, bytes, *tcp_flags;
    char *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct tcphdr tcphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;

    // Aloca a memória das variáveis
    src_mac = allocate_ustrmem(6);
    dst_mac = allocate_ustrmem(6);
    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    target = allocate_strmem(INET6_ADDRSTRLEN);
    src_ip = allocate_strmem(INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET6_ADDRSTRLEN);
    tcp_flags = allocate_intmem(8);

    // abertura do socket
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("Falha ao executar socket(). Falha ao criar socket descriptor usando ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Obter MAC da interface passada por parâmetro
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Falha ao executar ioctl(). Falha ao obter MAC address de origem.");
        return (EXIT_FAILURE);
    }
    // close (sd);

    // Copia Mac Address
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    // Copia o device
    memset(&device, 0, sizeof(device));

    // Atribui a interface pro device
    device.sll_ifindex = if_nametoindex(interface);
    if (device.sll_ifindex == 0)
    {
        perror("Falha ao executar if_nametoindex(); Falha ao obter index da interface.");
        exit(EXIT_FAILURE);
    }

    // Mac de Destino
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // IPv6 de origem
    strcpy(src_ip, ip_origem);

    // IPv6 de destino
    strcpy(dst_ip, ip_destino);

    // Preenche os dados do device
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = 6;

    // Montagem do Cabeçalho IPv6

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Preenche o Payload (16 bits)
    iphdr.ip6_plen = htons(TCP_HDRLEN);

    // Preenche o Next header (8 bits): 6 para TCP
    iphdr.ip6_nxt = IPPROTO_TCP;

    // Preenche Hop limit (8 bits): definido maximo valor
    iphdr.ip6_hops = 255;

    // Preenche IPv6 de origem (128 bits)
    if ((status = inet_pton(AF_INET6, src_ip, &(iphdr.ip6_src))) != 1)
    {
        fprintf(stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de origem.\nMensagem: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Preenche IPv6 de destino (128 bits)
    if ((status = inet_pton(AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1)
    {
        fprintf(stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de destino.\nMensagem: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Montagem do Cabeçalho TCP

    // Porta de Origem (16 bits)
    tcphdr.th_sport = htons(60);

    // Porta de Destino (16 bits)
    tcphdr.th_dport = htons(porta);

    // Número de sequencia (32 bits)
    tcphdr.th_seq = htonl(0);

    // Numero do Acknowledgement (32 bits): 0 para o primeiro pacote do syn/ack
    tcphdr.th_ack = htonl(0);

    // Campo Reserved (4 bits)
    tcphdr.th_x2 = 0;

    // Offset (4 bits): tamanho do cabeçalho TCP em plavra de 32-bit
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN (1 bit)
    tcp_flags[0] = 0;

    // SYN (1 bit)
    tcp_flags[1] = 1;

    // RST (1 bit)
    tcp_flags[2] = 0;

    // PSH (1 bit)
    tcp_flags[3] = 0;

    // ACK (1 bit)
    tcp_flags[4] = 0;

    // URG (1 bit)
    tcp_flags[5] = 0;

    // ECE (1 bit)
    tcp_flags[6] = 0;

    // CWR (1 bit)
    tcp_flags[7] = 0;

    // Copia as flags
    tcphdr.th_flags = 0;
    for (i = 0; i < 8; i++)
    {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Tamanho da Janela
    tcphdr.th_win = htons(65535);

    // Ponteiro de Urgente
    tcphdr.th_urp = htons(0);

    // Calcula Checksum
    tcphdr.th_sum = tcp6_checksum(iphdr, tcphdr);

    // Montagem do frame ETHERNET

    // Define tamanho do Frame Ethernet
    frame_length = ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN;

    // Copia o MAC de destino para o frame
    memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));

    // Copia o MAC de origem para o frame
    memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Define o tipo de frame
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Copia os dados do header IP para o frame
    memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof(uint8_t));

    // Copia os dados do header TCP para o frame
    memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

    // Envia o pacote
    if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
    {
        perror("Falha ao executar função sendto(). Falha ao enviar pacote.");
        exit(EXIT_FAILURE);
    }
    while ((bytes = read(sd, ether_frame, frame_length)) > 0)
    {
        char src_ipv6[500] = "";
        char dst_ipv6[500] = "";
        int started = 0;

        for (i = 22; i < 37; i += 2)
        {
            if (started == 0)
            {
                started = 1;
            }
            else
            {
                strcat(src_ipv6, ":");
            }
            char tmp2[2];
            sprintf(tmp2, "%02x", ether_frame[i]);
            strcat(src_ipv6, tmp2);
            sprintf(tmp2, "%02x", ether_frame[i + 1]);
            strcat(src_ipv6, tmp2);
        }
        started = 0;

        // Le o IPv6 de destino do pacote recebido
        for (i = 38; i < 54; i += 2)
        {
            if (started == 0)
            {
                started = 1;
            }
            else
            {
                strcat(dst_ipv6, ":");
            }
            char tmp3[2];
            sprintf(tmp3, "%02x", ether_frame[i]);
            strcat(dst_ipv6, tmp3);
            sprintf(tmp3, "%02x", ether_frame[i + 1]);
            strcat(dst_ipv6, tmp3);
        }

        // Le a porta de origem do pacote recebido
        char src_port_2[4];
        sprintf(src_port_2, "%02x%02x", ether_frame[54], ether_frame[55]);

        // Converte a porta de origem hexa para long do pacote recebido
        long c = strtol(src_port_2, NULL, 16);

        // Le a porta de origem do pacote recebido
        char dst_port[4];
        sprintf(dst_port, "%02x%02x", ether_frame[56], ether_frame[57]);

        // Converte a porta de destino de hexa para long do pacote recebido
        long a = strtol(dst_port, NULL, 16);

        // Converte a porta de origem de decimal para long da porta definida para envio
        long b = strtol("60", NULL, 10);

        // Converte a porta de destino de decimal para long porta definida para envio
        long d = strtol(porta, NULL, 10);

        // Compara se os dados são iguais (ou seja, se o pacote recebido é a resposta do que foi enviado)
        // E se o pacote recebido foi um RST ou RST,ACK
        // Se for, informa que a porta está fechada e encerra o loop

        if (strcmp(dst_ip, src_ipv6) == 0 && strcmp(src_ip, dst_ipv6) == 0 && a == b && c == d && ether_frame[67] == 0x12)
        {

            tcp_flags[1] = 0;
            tcp_flags[2] = 0;
            tcp_flags[4] = 1;

            tcphdr.th_flags = 0;
            for (i = 0; i < 8; i++)
            {
                tcphdr.th_flags += (tcp_flags[i] << i);
            }

            //###################################
            // Preenche IPv6 de origem (128 bits)
            if ((status = inet_pton(AF_INET6, dst_ipv6, &(iphdr.ip6_src))) != 1)
            {
                fprintf(stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de origem.\nMensagem: %s", strerror(status));
                exit(EXIT_FAILURE);
            }

            // Preenche IPv6 de destino (128 bits)
            if ((status = inet_pton(AF_INET6, src_ipv6, &(iphdr.ip6_dst))) != 1)
            {
                fprintf(stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de destino.\nMensagem: %s", strerror(status));
                exit(EXIT_FAILURE);
            }

            // Copia o MAC de destino para o frame
            memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));

            // Copia o MAC de origem para o frame
            memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

            // Define o tipo de frame
            ether_frame[12] = ETH_P_IPV6 / 256;
            ether_frame[13] = ETH_P_IPV6 % 256;

            // Copia os dados do header IP para o frame
            memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof(uint8_t));

            // Copia os dados do header TCP para o frame
            memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));
            //##############################

            tcphdr.th_sum = tcp6_checksum(iphdr, tcphdr); //CORREÇÃO CHECKSUM
            memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

            if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
            {
                perror("Falha ao executar função sendto(). Falha ao enviar pacote.");
                exit(EXIT_FAILURE);
            }
            printf("Porta %d está ABERTA\n", d);
            break;
        }
        else if (ether_frame[67] & 0x14 || ether_frame[67] & 0x04)
        {
            printf("Porta %d está FECHADA\n", d);
            break;
        }
    }

    // Fecha o Socket
    close(sd);

    // Libera memória alocada
    free(src_mac);
    free(dst_mac);
    free(ether_frame);
    free(interface);
    free(src_ip);
    free(dst_ip);
    free(tcp_flags);

    return 0;
}

void TCP_HALF_OPENING (char *ip_origem, char *ip_destino, char *interface, int porta)
{
    // Variáveis
    int i, status, frame_length, sd, bytes, *tcp_flags;
    char *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct tcphdr tcphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;


    // Aloca a memória das variáveis
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    target = allocate_strmem (INET6_ADDRSTRLEN);
    src_ip = allocate_strmem (INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
    tcp_flags = allocate_intmem (8);


    // abertura do socket
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("Falha ao executar socket(). Falha ao criar socket descriptor usando ioctl() ");
		exit (EXIT_FAILURE);
    }

    // Obter MAC da interface passada por parâmetro
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("Falha ao executar ioctl(). Falha ao obter MAC address de origem.");
		return (EXIT_FAILURE);
    }
    // close (sd);

    // Copia Mac Address
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Copia o device
	memset (&device, 0, sizeof (device));

	// Atribui a interface pro device
	device.sll_ifindex = if_nametoindex (interface);
  	if (device.sll_ifindex == 0) {
    	perror ("Falha ao executar if_nametoindex(); Falha ao obter index da interface.");
    	exit (EXIT_FAILURE);
  	}

    // Mac de Destino
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // IPv6 de origem
    strcpy (src_ip, ip_origem);
    
    // IPv6 de destino
    strcpy (dst_ip, ip_destino);  
    
    // Preenche os dados do device
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;


    // Montagem do Cabeçalho IPv6
    
    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

    // Preenche o Payload (16 bits)
    iphdr.ip6_plen = htons (TCP_HDRLEN);

    // Preenche o Next header (8 bits): 6 para TCP
    iphdr.ip6_nxt = IPPROTO_TCP;

    // Preenche Hop limit (8 bits): definido maximo valor
    iphdr.ip6_hops = 255;

    // Preenche IPv6 de origem (128 bits)
    if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
		fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de origem.\nMensagem: %s", strerror (status));
		exit (EXIT_FAILURE);
    }
    
    // Preenche IPv6 de destino (128 bits)
    if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
		fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de destino.\nMensagem: %s", strerror (status));
		exit (EXIT_FAILURE);
    }


    // Montagem do Cabeçalho TCP
    
    // Porta de Origem (16 bits)
    tcphdr.th_sport = htons (60);

    // Porta de Destino (16 bits)
    tcphdr.th_dport = htons (porta);
    
    // Número de sequencia (32 bits)
    tcphdr.th_seq = htonl (0);

    // Numero do Acknowledgement (32 bits): 0 para o primeiro pacote do syn/ack
    tcphdr.th_ack = htonl (0);

    // Campo Reserved (4 bits)
    tcphdr.th_x2 = 0;

    // Offset (4 bits): tamanho do cabeçalho TCP em plavra de 32-bit
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN (1 bit)
    tcp_flags[0] = 0;

    // SYN (1 bit)
    tcp_flags[1] = 1;

    // RST (1 bit)
    tcp_flags[2] = 0;

    // PSH (1 bit)
    tcp_flags[3] = 0;

    // ACK (1 bit)
    tcp_flags[4] = 0;

    // URG (1 bit)
    tcp_flags[5] = 0;

    // ECE (1 bit)
    tcp_flags[6] = 0;

    // CWR (1 bit)
    tcp_flags[7] = 0;

    // Copia as flags
    tcphdr.th_flags = 0;
    for (i=0; i<8; i++) {
      tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Tamanho da Janela
    tcphdr.th_win = htons (65535);

    // Ponteiro de Urgente
    tcphdr.th_urp = htons (0);

    // Calcula Checksum
    tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr);

    // Montagem do frame ETHERNET

    // Define tamanho do Frame Ethernet
    frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN;

    // Copia o MAC de destino para o frame
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));

    // Copia o MAC de origem para o frame
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Define o tipo de frame
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Copia os dados do header IP para o frame
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

    // Copia os dados do header TCP para o frame
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

    // Envia o pacote
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("Falha ao executar função sendto(). Falha ao enviar pacote.");
      	exit (EXIT_FAILURE);
    }
	while ((bytes = read(sd, ether_frame, frame_length)) > 0){
		char src_ipv6[500] = "";
		char dst_ipv6[500] = "";
		int started = 0;
		
		for (i = 22; i < 37; i+=2){
			if(started == 0){
				started = 1;
			} else {
				strcat(src_ipv6,":");
			}
			char tmp2[2];
			sprintf(tmp2, "%02x", ether_frame[i]);
			strcat(src_ipv6,tmp2);
			sprintf(tmp2, "%02x", ether_frame[i +1]);
			strcat(src_ipv6,tmp2);
		}
		started = 0;

	  // Le o IPv6 de destino do pacote recebido
        
        for (i = 38; i < 54; i+=2){
			if(started == 0){
				started = 1;
			} else {
				strcat(dst_ipv6,":");
			}
			char tmp3[2];
			sprintf(tmp3, "%02x", ether_frame[i]);
			strcat(dst_ipv6,tmp3);
			sprintf(tmp3, "%02x", ether_frame[i +1]);
			strcat(dst_ipv6,tmp3);
        }
			
			// Le a porta de origem do pacote recebido
        char src_port_2[4];
        sprintf(src_port_2, "%02x%02x", ether_frame[54], ether_frame[55]);
		
		// Converte a porta de origem hexa para long do pacote recebido
		long c = strtol(src_port_2, NULL, 16);

		// Le a porta de origem do pacote recebido
        char dst_port[4];
        sprintf(dst_port, "%02x%02x", ether_frame[56], ether_frame[57]);

		// Converte a porta de destino de hexa para long do pacote recebido
		long a = strtol(dst_port, NULL, 16);

		// Converte a porta de origem de decimal para long da porta definida para envio
		long b = strtol("60", NULL, 10);

		// Converte a porta de destino de decimal para long porta definida para envio
		long d = strtol(porta, NULL, 10);
      
	  	// Compara se os dados são iguais (ou seja, se o pacote recebido é a resposta do que foi enviado)
		  // E se o pacote recebido foi um RST ou RST,ACK
		  // Se for, informa que a porta está fechada e encerra o loop
		
		if(strcmp(dst_ip,src_ipv6) == 0 
		&& strcmp(src_ip,dst_ipv6) == 0
		&& a == b
		&& c == d
		&& ether_frame[67] == 0x12){
			
			tcp_flags[1] = 0;
			tcp_flags[2] = 1;
			tcp_flags[4] = 0;

			tcphdr.th_flags = 0;
			
			for (i=0; i<8; i++) {
				tcphdr.th_flags += (tcp_flags[i] << i);
			}

			//###################################
			// Preenche IPv6 de origem (128 bits)
			if ((status = inet_pton (AF_INET6, dst_ipv6, &(iphdr.ip6_src))) != 1) {
				fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de origem.\nMensagem: %s", strerror (status));
				exit (EXIT_FAILURE);
			}
			
			// Preenche IPv6 de destino (128 bits)
			if ((status = inet_pton (AF_INET6, src_ipv6, &(iphdr.ip6_dst))) != 1) {
				fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de destino.\nMensagem: %s", strerror (status));
				exit (EXIT_FAILURE);
			}

			// Copia o MAC de destino para o frame
			memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));

			// Copia o MAC de origem para o frame
			memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

			// Define o tipo de frame
			ether_frame[12] = ETH_P_IPV6 / 256;
			ether_frame[13] = ETH_P_IPV6 % 256;

			// Copia os dados do header IP para o frame
			memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

			// Copia os dados do header TCP para o frame
			memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
			//##############################

			tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr); //CORREÇÃO CHECKSUM
			memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
				
			if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
				perror ("Falha ao executar função sendto(). Falha ao enviar pacote.");
				exit (EXIT_FAILURE);
			}
			printf("Porta %d está ABERTA\n", d);
		break;
			
		} else {
			printf("Porta %d está FECHADA\n", d);
			break;
		}

	}

	// Fecha o Socket
	close (sd);

	// Libera memória alocada
	free (src_mac);
	free (dst_mac);
	free (ether_frame);
	free (interface);
	free (src_ip);
	free (dst_ip);
	free (tcp_flags);

	return (EXIT_SUCCESS);
}

void STEALTH_SCAN (char *ip_origem, char *ip_destino, char *interface, int porta)
{
    // Variáveis
    int i, status, frame_length, sd, bytes, *tcp_flags;
    char *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct tcphdr tcphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;


    // Aloca a memória das variáveis
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    target = allocate_strmem (INET6_ADDRSTRLEN);
    src_ip = allocate_strmem (INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
    tcp_flags = allocate_intmem (8);


    // abertura do socket
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("Falha ao executar socket(). Falha ao criar socket descriptor usando ioctl() ");
		exit (EXIT_FAILURE);
    }

    // Obter MAC da interface passada por parâmetro
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("Falha ao executar ioctl(). Falha ao obter MAC address de origem.");
		return (EXIT_FAILURE);
    }
    // close (sd);

    // Copia Mac Address
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Copia o device
	memset (&device, 0, sizeof (device));

	// Atribui a interface pro device
	device.sll_ifindex = if_nametoindex (interface);
  	if (device.sll_ifindex == 0) {
    	perror ("Falha ao executar if_nametoindex(); Falha ao obter index da interface.");
    	exit (EXIT_FAILURE);
  	}

    // Mac de Destino
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // IPv6 de origem
    strcpy (src_ip, ip_origem);
    
    // IPv6 de destino
    strcpy (dst_ip, ip_destino);  
    
    // Preenche os dados do device
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;


    // Montagem do Cabeçalho IPv6
    
    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

    // Preenche o Payload (16 bits)
    iphdr.ip6_plen = htons (TCP_HDRLEN);

    // Preenche o Next header (8 bits): 6 para TCP
    iphdr.ip6_nxt = IPPROTO_TCP;

    // Preenche Hop limit (8 bits): definido maximo valor
    iphdr.ip6_hops = 255;

    // Preenche IPv6 de origem (128 bits)
    if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
		fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de origem.\nMensagem: %s", strerror (status));
		exit (EXIT_FAILURE);
    }
    
    // Preenche IPv6 de destino (128 bits)
    if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
		fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de destino.\nMensagem: %s", strerror (status));
		exit (EXIT_FAILURE);
    }


    // Montagem do Cabeçalho TCP
    
    // Porta de Origem (16 bits)
    tcphdr.th_sport = htons (60);

    // Porta de Destino (16 bits)
    tcphdr.th_dport = htons (porta);
    
    // Número de sequencia (32 bits)
    tcphdr.th_seq = htonl (0);

    // Numero do Acknowledgement (32 bits): 0 para o primeiro pacote do syn/ack
    tcphdr.th_ack = htonl (0);

    // Campo Reserved (4 bits)
    tcphdr.th_x2 = 0;

    // Offset (4 bits): tamanho do cabeçalho TCP em plavra de 32-bit
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN (1 bit)
    tcp_flags[0] = 1;

    // SYN (1 bit)
    tcp_flags[1] = 0;

    // RST (1 bit)
    tcp_flags[2] = 0;

    // PSH (1 bit)
    tcp_flags[3] = 0;

    // ACK (1 bit)
    tcp_flags[4] = 0;

    // URG (1 bit)
    tcp_flags[5] = 0;

    // ECE (1 bit)
    tcp_flags[6] = 0;

    // CWR (1 bit)
    tcp_flags[7] = 0;

    // Copia as flags
    tcphdr.th_flags = 0;
    for (i=0; i<8; i++) {
      tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Tamanho da Janela
    tcphdr.th_win = htons (65535);

    // Ponteiro de Urgente
    tcphdr.th_urp = htons (0);

    // Calcula Checksum
    tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr);

    // Montagem do frame ETHERNET

    // Define tamanho do Frame Ethernet
    frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN;

    // Copia o MAC de destino para o frame
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));

    // Copia o MAC de origem para o frame
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Define o tipo de frame
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Copia os dados do header IP para o frame
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

    // Copia os dados do header TCP para o frame
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

    // Envia o pacote
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("Falha ao executar função sendto(). Falha ao enviar pacote.");
      	exit (EXIT_FAILURE);
    }

	// Aguarda a resposta
    while ((bytes = read(sd, ether_frame, frame_length)) > 0){

		// Le o IPv6 de origem do pacote recebido
        int started = 0;
        char src_ipv6[500] = "";
        for (i = 22; i < 37; i+=2){
			if(started == 0){
				started = 1;
			} else {
				strcat(src_ipv6,":");
			}
			char tmp2[2];
			sprintf(tmp2, "%02x", ether_frame[i]);
			strcat(src_ipv6,tmp2);
			sprintf(tmp2, "%02x", ether_frame[i +1]);
			strcat(src_ipv6,tmp2);
        }
        started = 0;

		// Le o IPv6 de destino do pacote recebido
        char dst_iv6[500] = "";
        for (i = 38; i < 54; i+=2){
			if(started == 0){
				started = 1;
			} else {
				strcat(dst_iv6,":");
			}
			char tmp3[2];
			sprintf(tmp3, "%02x", ether_frame[i]);
			strcat(dst_iv6,tmp3);
			sprintf(tmp3, "%02x", ether_frame[i +1]);
			strcat(dst_iv6,tmp3);
        }
        
		// Le a porta de origem do pacote recebido
        char src_port_2[4];
        sprintf(src_port_2, "%02x%02x", ether_frame[54], ether_frame[55]);
		
		// Converte a porta de origem hexa para long do pacote recebido
		long c = strtol(src_port_2, NULL, 16);

		// Le a porta de origem do pacote recebido
        char dst_port[4];
        sprintf(dst_port, "%02x%02x", ether_frame[56], ether_frame[57]);

		// Converte a porta de destino de hexa para long do pacote recebido
		long a = strtol(dst_port, NULL, 16);

		// Converte a porta de origem de decimal para long da porta definida para envio
		long b = strtol("60", NULL, 10);

		// Converte a porta de destino de decimal para long porta definida para envio
		long d = strtol(porta, NULL, 10);
      
	  	// Compara se os dados são iguais (ou seja, se o pacote recebido é a resposta do que foi enviado)
		  // E se o pacote recebido foi um RST ou RST,ACK
		  // Se for, informa que a porta está fechada e encerra o loop
		if(strcmp(dst_ip,src_ipv6) == 0  
		&& strcmp(src_ip,dst_iv6) == 0 
		&& a == b 
		&& c == d 
		&& (ether_frame[67] == 0x14 
		|| ether_frame[67] == 0x04)) {
			printf("Porta %d está FECHADA \n", d);
			break;
		} else {
			printf("Porta %d está ABERTA \n", d);
			break;
		}
    }

    // Fecha o Socket
	close (sd);

	// Libera memória alocada
	free (src_mac);
	free (dst_mac);
	free (ether_frame);
	free (interface);
	free (src_ip);
	free (dst_ip);
	free (tcp_flags);

	return (EXIT_SUCCESS);
}

void STEALTH_SCAN (char *ip_origem, char *ip_destino, char *interface, int porta)
{
    // Variáveis
    int i, status, frame_length, sd, bytes, *tcp_flags;
    char *src_ip, *dst_ip;
    struct ip6_hdr iphdr;
    struct tcphdr tcphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;


	// Aloca a memória das variáveis
	src_mac = allocate_ustrmem (6);
	dst_mac = allocate_ustrmem (6);
	ether_frame = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	target = allocate_strmem (INET6_ADDRSTRLEN);
	src_ip = allocate_strmem (INET6_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
	tcp_flags = allocate_intmem (8);


	// abertura do socket
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("Falha ao executar socket(). Falha ao criar socket descriptor usando ioctl() ");
		exit (EXIT_FAILURE);
	}

	// Obter MAC da interface passada por parâmetro
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("Falha ao executar ioctl(). Falha ao obter MAC address de origem.");
		return (EXIT_FAILURE);
	}
	// close (sd);

	// Copia Mac Address
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

	// Copia o device
	memset (&device, 0, sizeof (device));

	// Atribui a interface pro device
	device.sll_ifindex = if_nametoindex (interface);
  	if (device.sll_ifindex == 0) {
		perror ("Falha ao executar if_nametoindex(); Falha ao obter index da interface.");
		exit (EXIT_FAILURE);
  	}

	// Mac de Destino
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	// IPv6 de origem
	strcpy (src_ip, ip_origem);
	
	// IPv6 de destino
	strcpy (dst_ip, ip_destino);  
	
	// Preenche os dados do device
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
	device.sll_halen = 6;


	// Montagem do Cabeçalho IPv6
	
	// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
	iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

	// Preenche o Payload (16 bits)
	iphdr.ip6_plen = htons (TCP_HDRLEN);

	// Preenche o Next header (8 bits): 6 para TCP
	iphdr.ip6_nxt = IPPROTO_TCP;

	// Preenche Hop limit (8 bits): definido maximo valor
	iphdr.ip6_hops = 255;

	// Preenche IPv6 de origem (128 bits)
	if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
		fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de origem.\nMensagem: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	
	// Preenche IPv6 de destino (128 bits)
	if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
		fprintf (stderr, "Falha na função inet_pton(). Falha ao preencher IPv6 de destino.\nMensagem: %s", strerror (status));
		exit (EXIT_FAILURE);
	}


	// Montagem do Cabeçalho TCP
	
	// Porta de Origem (16 bits)
	tcphdr.th_sport = htons (60);

	// Porta de Destino (16 bits)
	tcphdr.th_dport = htons (porta);
	
	// Número de sequencia (32 bits)
	tcphdr.th_seq = htonl (0);

	// Numero do Acknowledgement (32 bits): 0 para o primeiro pacote do syn/ack
	tcphdr.th_ack = htonl (0);

	// Campo Reserved (4 bits)
	tcphdr.th_x2 = 0;

	// Offset (4 bits): tamanho do cabeçalho TCP em plavra de 32-bit
	tcphdr.th_off = TCP_HDRLEN / 4;

	// Flags (8 bits)

	// FIN (1 bit)
	tcp_flags[0] = 0;

	// SYN (1 bit)
	tcp_flags[1] = 1;

	// RST (1 bit)
	tcp_flags[2] = 0;

	// PSH (1 bit)
	tcp_flags[3] = 0;

	// ACK (1 bit)
	tcp_flags[4] = 1;

	// URG (1 bit)
	tcp_flags[5] = 0;

	// ECE (1 bit)
	tcp_flags[6] = 0;

	// CWR (1 bit)
	tcp_flags[7] = 0;

	// Copia as flags
	tcphdr.th_flags = 0;
	for (i=0; i<8; i++) {
	  tcphdr.th_flags += (tcp_flags[i] << i);
	}

	// Tamanho da Janela
	tcphdr.th_win = htons (65535);

	// Ponteiro de Urgente
	tcphdr.th_urp = htons (0);

	// Calcula Checksum
	tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr);

	// Montagem do frame ETHERNET

	// Define tamanho do Frame Ethernet
	frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN;

	// Copia o MAC de destino para o frame
	memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));

	// Copia o MAC de origem para o frame
	memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

	// Define o tipo de frame
	ether_frame[12] = ETH_P_IPV6 / 256;
	ether_frame[13] = ETH_P_IPV6 % 256;

	// Copia os dados do header IP para o frame
	memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

	// Copia os dados do header TCP para o frame
	memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

	// Envia o pacote
	if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
	perror ("Falha ao executar função sendto(). Falha ao enviar pacote.");
	  	exit (EXIT_FAILURE);
	}

	// Aguarda a resposta
  	while ((bytes = read(sd, ether_frame, frame_length)) > 0){

		int started = 0;
		char src_ipv6[500] = "";
		for (i = 22; i < 37; i+=2){
			if(started == 0){
				started = 1;
			} else {
				strcat(src_ipv6,":");
			}
			char tmp2[2];
			sprintf(tmp2, "%02x", ether_frame[i]);
			strcat(src_ipv6,tmp2);
			sprintf(tmp2, "%02x", ether_frame[i +1]);
			strcat(src_ipv6,tmp2);
		}
		started = 0;

	  // Le o IPv6 de destino do pacote recebido
        char dst_iv6[500] = "";
        for (i = 38; i < 54; i+=2){
			if(started == 0){
				started = 1;
			} else {
				strcat(dst_iv6,":");
			}
			char tmp3[2];
			sprintf(tmp3, "%02x", ether_frame[i]);
			strcat(dst_iv6,tmp3);
			sprintf(tmp3, "%02x", ether_frame[i +1]);
			strcat(dst_iv6,tmp3);
        }
	  
	  // Le a porta de origem do pacote recebido
        char src_port_2[4];
        sprintf(src_port_2, "%02x%02x", ether_frame[54], ether_frame[55]);
		
		// Converte a porta de origem hexa para long do pacote recebido
		long c = strtol(src_port_2, NULL, 16);

		// Le a porta de origem do pacote recebido
        char dst_port[4];
        sprintf(dst_port, "%02x%02x", ether_frame[56], ether_frame[57]);

		// Converte a porta de destino de hexa para long do pacote recebido
		long a = strtol(dst_port, NULL, 16);

		// Converte a porta de origem de decimal para long da porta definida para envio
		long b = strtol("60", NULL, 10);

		// Converte a porta de destino de decimal para long porta definida para envio
		long d = strtol(porta, NULL, 10);
      
	  	// Compara se os dados são iguais (ou seja, se o pacote recebido é a resposta do que foi enviado)
		  // E se o pacote recebido foi um RST ou RST,ACK
		  // Se for, informa que a porta está fechada e encerra o loop
	
		if(strcmp(dst_ip,src_ipv6) == 0 
		&& strcmp(src_ip,dst_iv6) == 0
		&& a == b
		&& c == d
		&& (ether_frame[67] & 0x14
		|| ether_frame[67] & 0x04)){
			printf("Porta %d está ABERTA \n", d);
			break;
		} else {
			printf("Porta %d está FECHADA \n", d);
			break;
		}
	}

  // Fecha o Socket
	close (sd);

	// Libera memória alocada
	free (src_mac);
	free (dst_mac);
	free (ether_frame);
	free (interface);
	free (src_ip);
	free (dst_ip);
	free (tcp_flags);

  return (EXIT_SUCCESS);
}

int main(int argc, char **argv)
{

    char *interface = NULL, *source = NULL, *dest = NULL;
    int portaIni, portaFim, operacao;

    if (argc < 6)
    {
        printf("usage:  sudo ./main IP_ORIGEM IP_DESTINO INTERFACE OPERACAO PORTA_INI PORTA_FIM\n");
        printf("  OPERACAO:\n");
        printf("    0: SNIFFER\n");
        printf("    1: TCP_CONNECT\n");
        printf("    2: TCP_HALF_OPENING\n");
        printf("    3: STEALTH_SCAN\n");
        printf("    4: SYN_ACK\n");
        return 0;
    }
    else
    {
        strcpy(source, argv[1]);
        strcpy(dest, argv[2]);
        strcpy(interface, argv[3]);
        operacao = atoi(argv[4]);
        portaIni = atoi(argv[5]);
        portaFim = atoi(argv[6]);
    }

    for (int i = portaIni; i <= portaFim; i++)
    {
        switch (operacao)
        {
            case 0:
                // SNIFFER()
                break

            case 1: // TCP_CONNECT
                TCP_CONNECT (source, dest, interface, i);
                break;

            case 2: // TCP_HALF_OPENING
                TCP_HALF_OPENING(source, dest, interface, i);
                break;

            case 3: // STEALTH_SCAN
                STEALTH_SCAN(source, dest, interface, i);
                break;

            case 4: // SYN_ACK
                SYN_ACK(source, dest, interface, i);
                break;

            default:
                break;
        }
    }

    for (int i = portaIni; i <= portaFim; i++)
    {
        if (strcmp(attack, TCP_CONNECT) == 0)
        {
            char *tmp = "./bin/tcp_connect ";
            char command[SIZE];
            strcpy(command, tmp);
            char port[5];
            sprintf(port, "%d", i);

            strcat(command, port);
            strcat(command, " ");
            strcat(command, interface);
            strcat(command, " ");
            strcat(command, source);
            strcat(command, " ");
            strcat(command, dest);
            int status = system(command);
        }
        else if (strcmp(attack, TCP_HALF_OPENING) == 0)
        {
            char *tmp = "./bin/tcp_half_opening ";
            char command[SIZE];
            strcpy(command, tmp);
            char port[5];
            sprintf(port, "%d", i);

            strcat(command, port);
            strcat(command, " ");
            strcat(command, interface);
            strcat(command, " ");
            strcat(command, source);
            strcat(command, " ");
            strcat(command, dest);
            int status = system(command);
        }
        else if (strcmp(attack, STEALTH_SCAN) == 0)
        {
            char *tmp = "./bin/stealth_scan_fin ";
            char command[SIZE];
            strcpy(command, tmp);
            char port[5];

            sprintf(port, "%d", i);

            strcat(command, port);
            strcat(command, " ");
            strcat(command, interface);
            strcat(command, " ");
            strcat(command, source);
            strcat(command, " ");
            strcat(command, dest);
            int status = system(command);
        }
        else
        {
            char *tmp = "./bin/syn_ack ";
            char command[SIZE];
            strcpy(command, tmp);
            char port[5];

            sprintf(port, "%d", i);

            strcat(command, port);
            strcat(command, " ");
            strcat(command, interface);
            strcat(command, " ");
            strcat(command, source);
            strcat(command, " ");
            strcat(command, dest);
            int status = system(command);
        }
    }

    return 0;
}

// Aloca memória para um array de char.
char *allocate_strmem(int len)
{
	void *tmp;

	if (len <= 0)
	{
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (char *)malloc(len * sizeof(char));
	if (tmp != NULL)
	{
		memset(tmp, 0, len * sizeof(char));
		return (tmp);
	}
	else
	{
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Aloca memória para um array de unsigned char.
uint8_t *allocate_ustrmem(int len)
{
	void *tmp;

	if (len <= 0)
	{
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (uint8_t *)malloc(len * sizeof(uint8_t));
	if (tmp != NULL)
	{
		memset(tmp, 0, len * sizeof(uint8_t));
		return (tmp);
	}
	else
	{
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Aloca memória para um array de inteiros
int *allocate_intmem(int len)
{
	void *tmp;

	if (len <= 0)
	{
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (int *)malloc(len * sizeof(int));
	if (tmp != NULL)
	{
		memset(tmp, 0, len * sizeof(int));
		return (tmp);
	}
	else
	{
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit(EXIT_FAILURE);
	}
}
