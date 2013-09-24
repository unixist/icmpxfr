#define OPT_HELP 1
#define OPT_EXEC_MODE 2
#define OPT_FILENAME 4
#define OPT_RESPOND_TO_CLIENT 8
#define OPT_OUTPUT_HASH 16
#define OPT_DST_IP 32
#define OPT_SRC_IP 64
#define OPT_EXPECT_RESPONSE 64
#define OPT_TRANSMIT_INTERVAL 128
#define OPT_LIKE_PING 256
#define OPT_PAYLOAD_LENGTH 512

struct options {
  unsigned long long flags;
} options;

unsigned short checksum (unsigned short *addr, int len);
void fill_ip_packet(struct ip *pkt, u_short data_len, const char *src, const char *dst);
void fill_icmp_packet(struct icmp *pkt, u_int16_t id, unsigned const char *payload, size_t payload_len, size_t icmp_len);
