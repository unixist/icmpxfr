/*
Compile: gcc -o icmp_client -Wall -lcrypto icmp_client.c
ICMP data transfer client
Copyright (C) 2011 Sean Williams

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

unsigned short checksum (unsigned short *addr, int len)
{
   int nleft = len;
   int sum = 0;
   unsigned short *w = addr;
   unsigned short answer = 0;
   while (nleft > 1){
      sum += *w++;
      nleft -= 2;
   }
   if (nleft == 1){
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;
   return (answer);
}

void fill_ip_packet(struct ip *pkt, u_short data_len, char *dst){
   struct in_addr addr;
   inet_pton(AF_INET, dst, &addr);
   pkt->ip_v = 4;
   pkt->ip_hl = 5;
   pkt->ip_tos = 0;
   pkt->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr) + data_len);
   pkt->ip_id = 9;
   pkt->ip_off = 0;
   pkt->ip_ttl = 255;
   pkt->ip_p = IPPROTO_ICMP;
   //pkt->ip_src.s_addr = inet_addr("1.2.3.4");
   pkt->ip_src.s_addr = htonl(INADDR_ANY);
   pkt->ip_dst.s_addr = addr.s_addr;
   pkt->ip_sum = 0;
   pkt->ip_sum = checksum((unsigned short *) pkt, sizeof(struct ip));
}

void fill_icmp_packet(struct icmp *pkt, unsigned char *payload, size_t payload_len, size_t icmp_len){
   pkt->icmp_type = ICMP_ECHO;
   pkt->icmp_code = 0;
   pkt->icmp_id = 9;
   pkt->icmp_seq = pkt->icmp_seq ? pkt->icmp_seq++ : 0;
   memcpy (pkt->icmp_data, payload, payload_len);
   pkt->icmp_cksum = 0;
   pkt->icmp_cksum = checksum((unsigned short *) pkt, icmp_len);
}

void usage(){
   fprintf(stderr, "Usage: ./bin -d <ip> [-f <filename>]\n");
   exit(EXIT_SUCCESS);
}

int main (int argc, char **argv){
   char *dst_ip = NULL;
   char buf_incoming[1500];
   char buf_outgoing[1500];
   unsigned char payload[50];
   struct sockaddr_in dst;
   struct ether_header *eth_hdr;
   struct ip *ip_hdr_in, *ip_hdr_out;
   struct icmp *icmp_hdr_in, *icmp_hdr_out;
   int one = 1;
   int ret = 0;
   int sock_eth;
   int sock_icmp;
   int ip_len;
   int icmp_len;
   int opt = 0;
   int locked = 0;
   u_short payload_len;

   while ((opt = getopt(argc, argv, "hd:")) != -1) {
      switch (opt) {
      case 'd':
         dst_ip = optarg;
         break;
      case 'h':
      default:
         usage();
      }
   }
   if (!dst_ip){
      usage();
   }

   if ((sock_eth = socket (AF_INET, SOCK_PACKET, htons (ETH_P_ALL))) < 0){
      perror ("socket");
      exit(1);
   }
   if ((sock_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
      perror ("socket");
      exit(1);
   }
   if ((ret = setsockopt (sock_icmp, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof (one))) < 0){
      perror("setsockopt");
      exit(1);
   }

   fcntl(sock_icmp, SOCK_NONBLOCK);
   memset(buf_incoming, 0, sizeof(buf_incoming));
   memset(buf_outgoing, 0, sizeof(buf_outgoing));
   // Initialize references to incoming packet
   // Point ethernet header to beginning of buffer
   eth_hdr = (struct ether_header *) buf_incoming;
   // Point IP header just after ethernet header
   ip_hdr_in = (struct ip *) (buf_incoming + sizeof (struct ether_header));
   // Point ICMP header just after IP header
   icmp_hdr_in = (struct icmp *) ((unsigned char *) ip_hdr_in + sizeof (struct ip));

   // Initialize references to outgoing packet
   ip_hdr_out = (struct ip *) buf_outgoing;
   icmp_hdr_out = (struct icmp *) (buf_outgoing + sizeof(struct ip));

   memset(payload, 0, sizeof(payload));
   while(!locked){
      payload_len = 4;
      payload[0] = 0xd; payload[1] = 0xc; payload[2] = 0xb; payload[3] = 0xa;
      fill_ip_packet(ip_hdr_out, payload_len, dst_ip);
      ip_len = ntohs(ip_hdr_out->ip_len);
      icmp_len = ip_len - sizeof(struct iphdr);
      fill_icmp_packet(icmp_hdr_out, payload, payload_len, icmp_len);
      dst.sin_family = AF_INET;
      dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;
      ret = sendto(sock_icmp, buf_outgoing, ip_len, 0, (struct sockaddr *) &dst, sizeof(dst)) != -1;

      memset(buf_incoming, 0, sizeof(buf_incoming));
      ret = recv(sock_eth, buf_incoming, sizeof(buf_incoming), 0);
      if (ip_hdr_in->ip_p == IPPROTO_ICMP && icmp_hdr_in->icmp_type == ICMP_ECHOREPLY){
         if (icmp_hdr_in->icmp_data[0] == 0xd && icmp_hdr_in->icmp_data[1] == 0xc &&
            icmp_hdr_in->icmp_data[2] == 0xb && icmp_hdr_in->icmp_data[3] == 0xa){
            locked = 1;
         }
      }
   }

   close(sock_eth);
   close(sock_icmp);
   return 0;
}
