#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#include "common.h"

unsigned short checksum (unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

void fill_ip_packet(struct ip *pkt, u_short data_len, const char *src, const char *dst) {
  struct in_addr addr;
  inet_pton(AF_INET, dst, &addr);
  pkt->ip_v = 4;
  pkt->ip_hl = 5;
  pkt->ip_tos = 0;
  pkt->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr) + data_len);
  pkt->ip_id = 9;
  pkt->ip_off = 0;
  pkt->ip_ttl = 128;
  pkt->ip_p = IPPROTO_ICMP;
  pkt->ip_src.s_addr = inet_addr(src == NULL ? "1.3.3.7" : src);
  pkt->ip_dst.s_addr = addr.s_addr;
  pkt->ip_sum = 0;
  pkt->ip_sum = checksum((unsigned short *) pkt, sizeof(struct ip));
}

void fill_icmp_packet(struct icmp *pkt, u_int16_t id, unsigned const char *payload, size_t payload_len, size_t icmp_len) {
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_code = 0;
  pkt->icmp_id = 0;
  if (pkt->icmp_seq)
    pkt->icmp_seq = htons(ntohs(pkt->icmp_seq)+1);
  else
    pkt->icmp_seq = 0;
  memcpy(pkt->icmp_data, payload, payload_len);
  pkt->icmp_cksum = 0;
  pkt->icmp_cksum = checksum((unsigned short *) pkt, icmp_len);
}
