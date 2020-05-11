#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <poll.h>
#include <unistd.h>
#include <zircon/compiler.h>
#include <zircon/syscalls.h>
#include <sys/socket.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define USEC_TO_MSEC(x) (float(x) / 1000.0)
#define RES_ICMP 1

const int MAX_PAYLOAD_SIZE_BYTES = 1400;

typedef struct {
  icmphdr hdr;
  uint32_t payload[MAX_PAYLOAD_SIZE_BYTES];
} __PACKED packet_t;


struct Options {
  long interval_msec = 1000;
  long payload_size_bytes = 0;
  long timeout_msec = 1000;
  const char* host = nullptr;
  long min_payload_size_bytes = 0;

  explicit Options(long min) {
    payload_size_bytes = min;
    min_payload_size_bytes = min;
  }

  void Print() const {
    printf("Payload size: %ld bytes, ", payload_size_bytes);
    printf("Interval: %ld ms, ", interval_msec);
    printf("Timeout: %ld ms, ", timeout_msec);
    if (host != nullptr) {
      printf("Destination: %s\n", host);
    }
  }

  bool Validate() const {
    if (interval_msec <= 0) {
      fprintf(stderr, "interval must be positive: %ld\n", interval_msec);
      return false;
    }

    if (payload_size_bytes >= MAX_PAYLOAD_SIZE_BYTES) {
      fprintf(stderr, "payload size must be smaller than: %d\n", MAX_PAYLOAD_SIZE_BYTES);
      return false;
    }

    if (payload_size_bytes < min_payload_size_bytes) {
      fprintf(stderr, "payload size must be more than: %ld\n", min_payload_size_bytes);
      return false;
    }

    if (timeout_msec <= 0) {
      fprintf(stderr, "timeout must be positive: %ld\n", timeout_msec);
      return false;
    }

    if (host == nullptr) {
      fprintf(stderr, "destination must be provided\n");
      return false;
    }
    return true;
  }

  int Usage() const {
    fprintf(stderr, "\n\tUsage: traceroute [ <option>* ] destination\n");
    fprintf(stderr, "\n\tSend ICMP ECHO_REQUEST to a destination. This destination\n");
    fprintf(stderr, "\tmay be a hostname (google.com) or an IP address (8.8.8.8).\n\n");
    fprintf(stderr, "\t-i interval(ms): Time interval between traceroutes (default = 1000)\n");
    fprintf(stderr, "\t-t timeout(ms): Timeout waiting for traceroute response (default = 1000)\n");
    fprintf(stderr, "\t-s size(bytes): Number of payload bytes (default = %ld, max 1400)\n",
            payload_size_bytes);
    fprintf(stderr, "\t-h: View this help message\n\n");
    return -1;
  }

  int ParseCommandLine(int argc, char** argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:c:i:t:h")) != -1) {
      char* endptr = nullptr;
      switch (opt) {
        case 'h':
          return Usage();
        case 'i':
          interval_msec = strtol(optarg, &endptr, 10);
          if (*endptr != '\0') {
            fprintf(stderr, "-i must be followed by a non-negative integer\n");
            return Usage();
          }
          break;
        case 's':
          payload_size_bytes = strtol(optarg, &endptr, 10);
          if (*endptr != '\0') {
            fprintf(stderr, "-s must be followed by a non-negative integer\n");
            return Usage();
          }
          break;
        case 't':
          timeout_msec = strtol(optarg, &endptr, 10);
          if (*endptr != '\0') {
            fprintf(stderr, "-t must be followed by a non-negative integer\n");
            return Usage();
          }
          break;
        default:
          return Usage();
      }
    }
    if (optind >= argc) {
      fprintf(stderr, "missing destination\n");
      return Usage();
    }
    host = argv[optind];
    return 0;
  }
};

struct tracerouteStatistics {
  uint64_t min_rtt_usec = UINT64_MAX;
  uint64_t max_rtt_usec = 0;
  uint64_t sum_rtt_usec = 0;
  uint16_t num_sent = 0;
  uint16_t num_lost = 0;

  void Update(uint64_t rtt_usec) {
    if (rtt_usec < min_rtt_usec) {
      min_rtt_usec = rtt_usec;
    }
    if (rtt_usec > max_rtt_usec) {
      max_rtt_usec = rtt_usec;
    }
    sum_rtt_usec += rtt_usec;
    num_sent++;
  }

  void Print() const {
    if (num_sent == 0) {
      printf("No probe sent\n");
      return;
    }
    printf("RTT Min/Max/Avg = [ %.3f / %.3f / %.3f ] ms\n", USEC_TO_MSEC(min_rtt_usec),
           USEC_TO_MSEC(max_rtt_usec), USEC_TO_MSEC(sum_rtt_usec / num_sent));
  }
};

int print_address(ssize_t r, uint32_t address, int ttl, uint64_t usec) {
  int a, b, c, d;
  a = address & 255;
  address = address >> 8;
  b = address & 255;
  address = address >> 8;
  c = address & 255;
  address = address >> 8;
  d = address & 255;
  printf("Node %d %d.%d.%d.%d : rtt=%.3f ms\n", ttl, a, b, c, d, (float)usec / 1000.0);
  return 0;
}

int main(int argc, char** argv) {
  constexpr char traceroute_message[] = "Sending on behalf of Traceroute!";
  long message_size = static_cast<long>(strlen(traceroute_message) + 1);
  Options options(message_size);
  tracerouteStatistics stats;

  if (options.ParseCommandLine(argc, argv) != 0) {
    return -1;
  }

  if (!options.Validate()) {
    return options.Usage();
  }

  options.Print();

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_flags = 0;
  struct addrinfo* info;
  if (getaddrinfo(options.host, NULL, &hints, &info)) {
    fprintf(stderr, "traceroute: unknown host %s\n", options.host);
    return -1;
  }

  int proto;
  uint8_t type;
  switch (info->ai_family) {
    case AF_INET: {
      proto = IPPROTO_ICMP;
      type = ICMP_ECHO;
      char buf[INET_ADDRSTRLEN];
      auto addr = reinterpret_cast<struct sockaddr_in*>(info->ai_addr);
      printf("traceroute4 %s (%s)\n", options.host,
             inet_ntop(info->ai_family, &addr->sin_addr, buf, sizeof(buf)));
      break;
    }
    case AF_INET6: {
      proto = IPPROTO_ICMPV6;
      type = ICMP_ECHO;
      char buf[INET6_ADDRSTRLEN];
      auto addr = reinterpret_cast<struct sockaddr_in6*>(info->ai_addr);
      printf("traceroute6 %s (%s)\n", options.host,
             inet_ntop(info->ai_family, &addr->sin6_addr, buf, sizeof(buf)));
      break;
    }
    default:
      fprintf(stderr, "traceroute: unknown address family %d\n", info->ai_family);
      return -1;
  }

  uint16_t sequence = 1;
  const zx_ticks_t ticks_per_usec = zx_ticks_per_second() / 1000000;
  int ttl = 1;
  packet_t packet;
  packet_t received_packet;
  ssize_t r = 0;
  ssize_t sent_packet_size = 0;
  bool reached = false;
  while (!reached) {
    memset(&packet, 0, sizeof(packet));
    memset(&received_packet, 0, sizeof(received_packet));
    packet.hdr.type = type;
    packet.hdr.code = 0;
    packet.hdr.un.echo.id = 0;
    packet.hdr.un.echo.sequence = htons(sequence++);
    strcpy(reinterpret_cast<char*>(packet.payload), traceroute_message);
    zx_ticks_t before = zx_ticks_get();
    int s = socket(info->ai_family, SOCK_DGRAM, proto);
    if (s < 0) {
      fprintf(stderr, "Could not acquire ICMP socket: %s\n", strerror(errno));
      return -1;
    }
    if(setsockopt(s, IPPROTO_IP, IP_TTL, (char*)(&ttl), sizeof(ttl)) < 0) {
      fprintf(stderr, "traceroute: Could not change TTL: %s\n", stderror(errno));
      return -1;
    }
    sent_packet_size = sizeof(packet.hdr) + options.payload_size_bytes;
    r = sendto(s, &packet, sent_packet_size, 0, info->ai_addr, info->ai_addrlen);
    if (r < 0) {
      fprintf(stderr, "traceroute: Could not send packet: %s\n", strerror(errno));
      return -1;
    }
    struct sockaddr_in dest_addr;
    socklen_t dest_len = sizeof(dest_addr);
    memset(&dest_addr, 0, sizeof(dest_addr));
    struct pollfd fd;
    fd.fd = s;
    fd.events = (POLLIN | POLLERR);
    switch (poll(&fd, 1, static_cast<int>(options.timeout_msec))) {
      case 1:
        if (fd.revents & (POLLIN | POLLERR)) {
          r = recvfrom(s, &received_packet, sizeof(received_packet), 0, (struct sockaddr *)&dest_addr, &dest_len);
          if (received_packet.hdr.type == ICMP_ECHOREPLY || received_packet.hdr.type == ICMP6_ECHO_REPLY) {
            reached = true;
          }
          break;
        } else {
          fprintf(stderr, "traceroute: Spurious wakeup from poll\n");
          r = -1;
          break;
        }
      case 0:
        fprintf(stderr, "traceroute: Timeout after %d ms\n", static_cast<int>(options.timeout_msec));
        __FALLTHROUGH;
      default:
        r = -1;
    }
    if (r < 0) {
      fprintf(stderr, "traceroute: Could not read result\n");
      return -1;
    }
    zx_ticks_t after = zx_ticks_get();
    uint64_t usec = (after - before) / ticks_per_usec;
    stats.Update(usec);
    print_address(r, (dest_addr.sin_addr.s_addr), ttl, usec);
    if (!reached) {
      usleep(static_cast<unsigned int>(options.interval_msec * 1000));
    }
    ttl++;
    close(s);
  }
  freeaddrinfo(info);
  stats.Print();
  return 0;
}
