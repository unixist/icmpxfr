/*
Compile: gcc -o icmp_server -Wall -lcrypto icmp_server.c
ICMP data transfer server
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

void usage(){
   fprintf(stderr, "Usage: ./bin\n");
   exit(EXIT_SUCCESS);
}

int main (int argc, char **argv)
{
   int ret = 0;
   int one = 1;
   int sock_eth;
   int sock_icmp;
   int ip_len;
   int icmp_len;
   int icmp_data_in_len;
   int opt = 0;
   char print_hash = 1;
   char buf_incoming[1500];
   char buf_outgoing[1500];
   char payload[50];
   struct sockaddr_in dst;
   struct ether_header *eth_hdr;
   struct ip *ip_hdr_in, *ip_hdr_out;
   struct icmp *icmp_hdr_in, *icmp_hdr_out;

   while ((opt = getopt(argc, argv, "hncf:")) != -1) {
      switch (opt) {
         case 'n':
            print_hash = 0;
            break;
         case 'h':
         default:
            usage();
      }
   }

   if ((sock_eth = socket (AF_INET, SOCK_PACKET, htons (ETH_P_ALL))) < 0)
   {
      perror ("socket");
      exit (1);
    }
  if ((sock_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
      perror ("socket");
      exit (1);
    }
  if ((ret =
       setsockopt (sock_icmp, IPPROTO_IP, IP_HDRINCL, (char *) &one,
		   sizeof(one))) < 0)
    {
      perror ("setsockopt");
      exit (1);
    }

   eth_hdr = (struct ether_header *) buf_incoming;

   ip_hdr_in = (struct ip *) (buf_incoming + sizeof(struct ether_header));
   icmp_hdr_in = (struct icmp *) ((unsigned char *) ip_hdr_in + sizeof(struct ip));

   ip_hdr_out = (struct ip *) buf_outgoing;
   icmp_hdr_out = (struct icmp *) (buf_outgoing + sizeof(struct ip));

   while ((ret = recv (sock_eth, buf_incoming, sizeof(buf_incoming), 0)) > 0){
      if (ip_hdr_in->ip_p == IPPROTO_ICMP){
         if (icmp_hdr_in->icmp_type == ICMP_ECHO){
            ip_hdr_out->ip_v = ip_hdr_in->ip_v;
            ip_hdr_out->ip_hl = ip_hdr_in->ip_hl;
            ip_hdr_out->ip_tos = ip_hdr_in->ip_tos;
            ip_hdr_out->ip_len = ip_hdr_in->ip_len;
            ip_hdr_out->ip_id = ip_hdr_in->ip_id;
            ip_hdr_out->ip_off = 0;
            ip_hdr_out->ip_ttl = 255;
            ip_hdr_out->ip_p = IPPROTO_ICMP;
            ip_hdr_out->ip_sum = 0;
            ip_hdr_out->ip_src.s_addr = ip_hdr_in->ip_dst.s_addr;
            ip_hdr_out->ip_dst.s_addr = ip_hdr_in->ip_src.s_addr;
            ip_hdr_out->ip_sum = checksum ((unsigned short *) buf_outgoing, ip_hdr_out->ip_hl);

            icmp_hdr_out->icmp_type = ICMP_ECHOREPLY;
            icmp_hdr_out->icmp_code = 0;
            icmp_hdr_out->icmp_id = icmp_hdr_in->icmp_id;
            icmp_hdr_out->icmp_seq = icmp_hdr_in->icmp_seq + 1;
            icmp_hdr_out->icmp_cksum = 0;

            ip_len = ntohs(ip_hdr_in->ip_len);
            icmp_len = ip_len - sizeof(struct iphdr);
            icmp_data_in_len = ntohs(ip_hdr_in->ip_len) - sizeof(struct ip) - sizeof(struct icmphdr);
            
            memset(payload, 0, sizeof(payload));
            if (icmp_data_in_len == 4 && icmp_hdr_in->icmp_data[0] == 0xd &&
               icmp_hdr_in->icmp_data[1] == 0xc && icmp_hdr_in->icmp_data[2] == 0xb && 
               icmp_hdr_in->icmp_data[3] == 0xa){
                  icmp_hdr_out->icmp_data[0] = 0xa;
                  icmp_hdr_out->icmp_data[1] = 0xb;
                  icmp_hdr_out->icmp_data[2] = 0xc;
                  icmp_hdr_out->icmp_data[3] = 0xd;

                  dst.sin_family = AF_INET;
                  dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;
                  icmp_hdr_out->icmp_cksum = checksum ((unsigned short *) icmp_hdr_out, icmp_len);
                  ret = sendto(sock_icmp, buf_outgoing, ip_len, 0, (struct sockaddr *) &dst, sizeof(dst));
                  if (ret < 0){
                     perror ("sendto");
                     exit(1);
                  }
            }
         }
      }
   }
   close(sock_eth);
   close(sock_icmp);
   return 0;
}
