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
#include <errno.h>
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

#include "common.h"

void usage() {
  fprintf(stderr, "Usage: ./bin [-hre] [-l packet length] [-d ip] [-f filename] [-i interval] [-s source]\n");
  exit(EXIT_SUCCESS);
}

int main (int argc, char **argv) {
  char *dst_ip = NULL;
  char *src_ip = NULL;
  char *filename = NULL;
  char buf_incoming[1500];
  char buf_outgoing[1500];
  char started = 0;
  char done = 0;
  unsigned char *payload;
  unsigned char *whole_file;
  unsigned char sha1_hash[20];
  struct options opts;
  struct sockaddr_in dst;
  struct ether_header *eth_hdr;
  struct ip *ip_hdr_in, *ip_hdr_out;
  struct icmp *icmp_hdr_in, *icmp_hdr_out;
  int one = 1;
  int ret = 0;
  int fd;
  int sock_eth;
  int sock_icmp;
  int ip_len;
  int icmp_len;
  int opt = 0;
  int transmit_interval = 0;
  unsigned int max_payload_len = 56;
  unsigned const int WHOLE_FILE_LEN = 4096;
  unsigned long long pos = 0;
  unsigned long long whole_file_len = 0;
  u_short payload_len;

  while ((opt = getopt(argc, argv, "hrel:d:f:i:s:")) != -1) {
    switch (opt) {
    case 'f':
      opts.flags |= OPT_FILENAME;
      filename = optarg;
      break;
    case 'e':
      opts.flags |= OPT_EXEC_MODE;
      break;
    case 'd':
      opts.flags |= OPT_DST_IP;
      dst_ip = optarg;
      break;
    case 's':
      opts.flags |= OPT_SRC_IP;
      src_ip = optarg;
      break;
    case 'r':
      opts.flags |= OPT_EXPECT_RESPONSE;
      break;
    case 'l':
      opts.flags |= OPT_PAYLOAD_LENGTH;
      max_payload_len = strtoul(optarg, NULL, 10);
      break;
    case 'i':
      opts.flags |= OPT_TRANSMIT_INTERVAL;
      transmit_interval = strtoul(optarg, NULL, 10);
      if (transmit_interval > 0)
        transmit_interval = transmit_interval * 1000000;
      else
        transmit_interval = 30000;
      break;
    case 'p':
      opts.flags |= OPT_LIKE_PING;
      break;
    case 'h':
    default:
      usage();
    }
  }

  if (!(opts.flags & OPT_DST_IP) || (!(opts.flags & OPT_FILENAME) && !(opts.flags & OPT_EXEC_MODE))) {
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

  if (!(opts.flags & OPT_EXEC_MODE)) {
    if (opts.flags & OPT_FILENAME && filename) {
      if ((fd = open(filename, O_RDONLY)) == -1) {
        perror("open");
        exit(1);
      }
    } else{
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

  payload = malloc(max_payload_len);
  memset(whole_file, 0, WHOLE_FILE_LEN);
  do { 
    if (opts.flags & OPT_EXPECT_RESPONSE && started) {
      ret = recv(sock_eth, buf_incoming, sizeof (buf_incoming), 0);
    }
    memset(payload, 0, max_payload_len);
    if ((ret = read(fd, payload, max_payload_len)) == -1) {
      perror("read");
      exit(1);
    }
    if (ret == 0) {// End of file, send payload-end delimiter '\0'
      payload[0] = '\0';
      payload_len = 0;
      done = 1;
    } else {// Gather next bit of file
      payload_len = ret;
      if (pos + payload_len > WHOLE_FILE_LEN) {
        whole_file = realloc(whole_file, WHOLE_FILE_LEN + pos + payload_len);
        whole_file_len = pos + payload_len;
      } else {
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
    
    if (!started) started = 1;
  }while ((ret = sendto(sock_icmp, buf_outgoing, ip_len, 0, (struct sockaddr *) &dst, sizeof (dst)) != -1) && !done && usleep(transmit_interval) == 0);

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
