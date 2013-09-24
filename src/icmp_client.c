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
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <openssl/sha.h>

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
  pkt->ip_ttl = 255;
  pkt->ip_p = IPPROTO_ICMP;
  pkt->ip_src.s_addr = inet_addr(src == NULL ? "1.3.3.7" : src);
  pkt->ip_src.s_addr = htonl(INADDR_ANY);
  pkt->ip_dst.s_addr = addr.s_addr;
  pkt->ip_sum = 0;
  pkt->ip_sum = checksum((unsigned short *) pkt, sizeof(struct ip));
}

void fill_icmp_packet(struct icmp *pkt, u_int16_t id, unsigned const char *payload, size_t payload_len, size_t icmp_len) {
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_code = 0;
  pkt->icmp_id = id;
  if (pkt->icmp_seq)
    pkt->icmp_seq++;
  else
    pkt->icmp_seq = 0;
  memcpy (pkt->icmp_data, payload, payload_len);
  pkt->icmp_cksum = 0;
  pkt->icmp_cksum = checksum((unsigned short *) pkt, icmp_len);
}

void usage() {
  fprintf(stderr, "Usage: ./bin [-hrc] [-d ip] [-f filename] [-i interval] [-s source]\n");
  exit(EXIT_SUCCESS);
}

int main (int argc, char **argv) {
  char *dst_ip = NULL;
  char *src_ip = NULL;
  char *filename = NULL;
  char buf_incoming[1500];
  char buf_outgoing[1500];
  char started = 0;
  char exec_mode = 0;
  char expect_response = 0;
  unsigned char payload[50];
  unsigned char *whole_file;
  unsigned char sha1_hash[20];
  struct sockaddr_in dst;
  struct ether_header *eth_hdr;
  struct ip *ip_hdr_in, *ip_hdr_out;
  struct icmp *icmp_hdr_in, *icmp_hdr_out;
  int done = 0;
  int one = 1;
  int ret = 0;
  int fd;
  int sock_eth;
  int sock_icmp;
  int ip_len;
  int icmp_len;
  int opt = 0;
  int transmit_interval = 30000;
  unsigned const int WHOLE_FILE_LEN = 4096;
  unsigned long long pos = 0;
  unsigned long long whole_file_len = 0;
  u_short payload_len;

  while ((opt = getopt(argc, argv, "hrcd:f:i:s:")) != -1) {
    switch (opt) {
    case 'f':
      filename = optarg;
      break;
    case 'c':
      exec_mode = 1;
      break;
    case 'd':
      dst_ip = optarg;
      break;
    case 's':
      src_ip = optarg;
      break;
    case 'r':
      expect_response = 1;
      break;
    case 'i':
      transmit_interval = atoi(optarg);
      printf("interval=%d\n", transmit_interval);
      break;
    case 'h':
    default:
      usage();
    }
  }
  if (!dst_ip || (!filename && !exec_mode)) {
    usage();
  }

  if ((whole_file = malloc(WHOLE_FILE_LEN)) == NULL) {
    perror("malloc");
    exit(1);
  }
  if ((sock_eth = socket (AF_INET, SOCK_PACKET, htons (ETH_P_ALL))) < 0) {
    perror ("socket");
    exit(1);
  }
  if ((sock_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    perror ("socket");
    exit(1);
  }
  if ((ret = setsockopt (sock_icmp, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof (one))) < 0) {
    perror("setsockopt");
    exit(1);
  }

  if (!exec_mode) {
    if (filename) {
      if ((fd = open(filename, O_RDONLY)) == -1) {
        perror("open");
        exit(1);
      }
    }else{
      fd = STDIN_FILENO;
    }
  }

  // Construct references to incoming packet
  // Point ethernet header to beginning of buffer
  eth_hdr = (struct ether_header *) buf_incoming;
  // Point IP header just after ethernet header
  ip_hdr_in = (struct ip *) (buf_incoming + sizeof (struct ether_header));
  // Point ICMP header just after IP header
  icmp_hdr_in = (struct icmp *) ((unsigned char *) ip_hdr_in + sizeof (struct ip));

  // Construct outgoing packet
  ip_hdr_out = (struct ip *) buf_outgoing;
  icmp_hdr_out = (struct icmp *) (buf_outgoing + sizeof (struct ip));

  memset(whole_file, 0, WHOLE_FILE_LEN);
  do { 
    if (expect_response && started) {
      ret = recv(sock_eth, buf_incoming, sizeof (buf_incoming), 0);
    }
    memset(payload, 0, sizeof(payload));
    if ((ret = read(fd, payload, sizeof(payload))) == -1) {
      perror("read");
      exit(1);
    }
    if (ret == 0) {// End of file, send payload-end delimiter '.'
      payload[0] = '\0';
      payload_len = 0;
      done = 1;
    }else{// Gather next bit of file
      payload_len = ret;
      if (pos + payload_len > WHOLE_FILE_LEN) {
        whole_file = realloc(whole_file, WHOLE_FILE_LEN + pos + payload_len);
        whole_file_len = pos + payload_len;
      }else{
        whole_file_len += payload_len;
      }
      memcpy(whole_file + pos, payload, payload_len);
      pos += ret;
    }

    fill_ip_packet(ip_hdr_out, payload_len, src_ip, dst_ip);
    ip_len = ntohs(ip_hdr_out->ip_len);
    icmp_len = ip_len - sizeof(struct iphdr);
    fill_icmp_packet(icmp_hdr_out, icmp_hdr_in->icmp_id, payload, payload_len, icmp_len);

    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;
    usleep(transmit_interval); //ICMP is too fast!
    if (!started) started = 1;
  }while ((ret = sendto(sock_icmp, buf_outgoing, ip_len, 0, (struct sockaddr *) &dst, sizeof (dst)) != -1) && !done);

  // Calc and send the SHA1 file hash
  SHA1(whole_file, whole_file_len, sha1_hash);
  fill_ip_packet(ip_hdr_out, sizeof(sha1_hash), src_ip, dst_ip);
  ip_len = ntohs(ip_hdr_out->ip_len);
  icmp_len = ip_len - sizeof(struct iphdr);
  fill_icmp_packet(icmp_hdr_out, icmp_hdr_in->icmp_id, sha1_hash, sizeof(sha1_hash), icmp_len);
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;
  sendto(sock_icmp, buf_outgoing, ip_len, 0, (struct sockaddr *) &dst, sizeof (dst));

  if (whole_file)
    free(whole_file);
  close(fd);
  close(sock_eth);
  close(sock_icmp);
  return 0;
}
