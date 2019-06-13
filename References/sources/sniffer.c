

#include <stdio.h>
#include <stdlib.h>
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
#include <time.h>
#include <errno.h>

#define ETH_HDRLEN 14
#define IP6_HDRLEN 40
#define TCP_HDRLEN 20

uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{
  int i, status, frame_length, sd, bytes, *tcp_flags;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct tcphdr tcphdr;
  uint8_t *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  src_mac = allocate_ustrmem(6);
  dst_mac = allocate_ustrmem(6);
  ether_frame = allocate_ustrmem(IP_MAXPACKET);
  interface = allocate_strmem(40);
  target = allocate_strmem(INET6_ADDRSTRLEN);
  src_ip = allocate_strmem(INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem(INET6_ADDRSTRLEN);
  tcp_flags = allocate_intmem(8);

  strcpy(interface, argv[1]);

  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    perror("socket() failed to get socket descriptor for using ioctl() ");
    exit(EXIT_FAILURE);
  }

  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
  {
    perror("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close(sd);

  memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

  printf("MAC address for interface %s is ", interface);
  for (i = 0; i < 5; i++)
  {
    printf("%02x:", src_mac[i]);
  }
  printf("%02x\n", src_mac[5]);

  memset(&device, 0, sizeof(device));
  if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
  {
    perror("if_nametoindex() failed to obtain interface index ");
    exit(EXIT_FAILURE);
  }
  printf("Index for interface %s is %i\n", interface, device.sll_ifindex);

  strcpy(dst_ip, argv[2]);

  device.sll_family = AF_PACKET;
  memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
  device.sll_halen = 6;

  frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN;

  memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
  memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

  ether_frame[12] = ETH_P_IPV6 / 256;
  ether_frame[13] = ETH_P_IPV6 % 256;

  memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof(uint8_t));

  memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  int count = 0;
  clock_t start = clock();
  char current_ipv6[500] = "";
  uint8_t initial_code;
  uint8_t other_code;

  while ((bytes = read(sd, ether_frame, frame_length)) > 0)
  {

    if (start - clock() > 1000)
    {
      memset(current_ipv6, 0, 500 * sizeof(char));
      count = 0;
      initial_code = 0;
      other_code = 0;
    }

    int started = 0;
    char src_ipv6[500] = "";
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

    char dst_iv6[500] = "";
    for (i = 38; i < 54; i += 2)
    {
      if (started == 0)
      {
        started = 1;
      }
      else
      {
        strcat(dst_iv6, ":");
      }
      char tmp3[2];
      sprintf(tmp3, "%02x", ether_frame[i]);
      strcat(dst_iv6, tmp3);
      sprintf(tmp3, "%02x", ether_frame[i + 1]);
      strcat(dst_iv6, tmp3);
    }

    char src_port_2[4];
    sprintf(src_port_2, "%02x%02x", ether_frame[54], ether_frame[55]);
    long c = strtol(src_port_2, NULL, 16);
    char dst_port[4];
    sprintf(dst_port, "%02x%02x", ether_frame[56], ether_frame[57]);

    long a = strtol(dst_port, NULL, 16);
    long b = strtol("60", NULL, 10);
    //    long d = strtol(argv[1], NULL, 10);
    //    printf("%s\n", dst_iv6);
    //    printf("%s\n", dst_ip);
    //printf("%d\n",strcmp(current_ipv6,"") == 0);
    if (strcmp(dst_iv6, dst_ip) == 0 && (strcmp(current_ipv6, "") == 0 || strcmp(current_ipv6, src_ipv6) == 0))
    {

      strcpy(current_ipv6, src_ipv6);

      if (initial_code == 0)
      {
        initial_code = ether_frame[67];
      }
      else if (other_code == 0 && ether_frame[67] != initial_code && ether_frame[67] == 0x10)
      {
        other_code = ether_frame[67];
      }

      if (initial_code != 0)
      {
        count++;
      }

      if (count == strtol(argv[3], NULL, 10))
      {
        if (initial_code == 0x02)
        {
          printf("%02x\n", other_code);
          if (other_code != 0)
          {
            printf("Ataque TCP Connect: %s!! \n", src_ipv6);
          }
          else
          {
            printf("Ataque TCP Half_Opening: %s\n", src_ipv6);
          }
        }
        else if (initial_code == 0x01)
        {
          printf("Ataque TCP Fin: %s\n", src_ipv6);
        }
        else if (initial_code == 0x12)
        {
          printf("Ataque SYN/ACK: %s\n", src_ipv6);
        }
      }
    }
  }

  close(sd);

  free(src_mac);
  free(dst_mac);
  free(ether_frame);
  free(interface);
  free(src_ip);
  free(dst_ip);
  free(tcp_flags);

  return (EXIT_SUCCESS);
}

uint16_t
checksum(uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1)
  {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0)
  {
    sum += *(uint8_t *)addr;
  }

  while (sum >> 16)
  {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;

  return (answer);
}

char *allocate_strmem(int len)
{
  void *tmp;

  if (len <= 0)
  {
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
    exit(EXIT_FAILURE);
  }
}

uint8_t *allocate_ustrmem(int len)
{
  void *tmp;

  if (len <= 0)
  {
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
    exit(EXIT_FAILURE);
  }
}

int *allocate_intmem(int len)
{
  void *tmp;

  if (len <= 0)
  {
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
    exit(EXIT_FAILURE);
  }
}
