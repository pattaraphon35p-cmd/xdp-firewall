// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def {
  __u32 type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
};

struct lpm_v4_key {
  __u32 prefixlen;
  __u8 addr[4];
};

struct http_rate_value {
  __u64 window_start_ns;
  __u32 syn_count;
  __u32 pure_ack_count;
  __u32 data_ack_count;
  __u32 fin_count;
  __u32 packet_count;
  __u32 violations;
};

struct http_l7_value {
  __u64 window_start_ns;
  __u32 data_packets;
  __u32 violations;
};

struct guard_stats {
  __u64 total_packets;
  __u64 passed_packets;
  __u64 dropped_packets;
  __u64 allowed_by_ip;
  __u64 allowed_by_cidr;
  __u64 denied_by_allowlist;
  __u64 dropped_by_syn_rate;
  __u64 dropped_by_ack_rate;
  __u64 dropped_by_fin_rate;
  __u64 dropped_by_packet_rate;
  __u64 dropped_by_l7_rate;
};

struct drop_event {
  __u64 ts_ns;
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 tcp_flags;
  __u8 reason;
  __u16 pad;
};

enum drop_reason {
  DROP_REASON_NONE = 0,
  DROP_REASON_SOURCE_NOT_ALLOWED = 1,
  DROP_REASON_HTTP_SYN_RATE = 2,
  DROP_REASON_HTTP_ACK_RATE = 3,
  DROP_REASON_HTTP_FIN_RATE = 4,
  DROP_REASON_HTTP_PACKET_RATE = 5,
  DROP_REASON_HTTP_L7_RATE = 6,
};

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define IP_FLAG_MF 0x2000
#define IP_FRAG_OFFSET_MASK 0x1FFF
#define WINDOW_NS 1000000000ULL
#define ETH_HLEN_BYTES 14
#define IPV4_HLEN_BYTES 20
#define TCP_HLEN_BYTES 20
#define MIN_HTTP_FRAME_BYTES (ETH_HLEN_BYTES + IPV4_HLEN_BYTES + TCP_HLEN_BYTES)

const volatile __u32 http_syn_limit_per_sec = 12;
const volatile __u32 http_syn_block_threshold = 36;
const volatile __u32 http_ack_limit_per_sec = 140;
const volatile __u32 http_ack_block_threshold = 320;
const volatile __u32 http_fin_limit_per_sec = 28;
const volatile __u32 http_fin_block_threshold = 84;
const volatile __u32 http_packet_limit_per_sec = 220;
const volatile __u32 http_packet_block_threshold = 520;
const volatile __u32 http_l7_data_limit_per_sec = 160;
const volatile __u32 http_l7_data_block_threshold = 320;

struct bpf_map_def SEC("maps") stats_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct guard_stats),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") http_allow_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 16384,
};

struct bpf_map_def SEC("maps") http_allow_cidrs = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_v4_key),
    .value_size = sizeof(__u8),
    .max_entries = 1024,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") http_rate_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct http_rate_value),
    .max_entries = 131072,
};

struct bpf_map_def SEC("maps") http_l7_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct http_l7_value),
    .max_entries = 131072,
};

#define INC_STAT(s, field)                                                     \
  do {                                                                         \
    if (s)                                                                     \
      (s)->field++;                                                            \
  } while (0)

static __always_inline void emit_drop_event(__u8 reason, __u32 src_ip_host,
                                            __u32 dst_ip_host, __u16 src_port,
                                            __u16 dst_port, __u8 tcp_flags) {
  struct drop_event *event;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return;

  event->ts_ns = bpf_ktime_get_ns();
  event->src_ip = src_ip_host;
  event->dst_ip = dst_ip_host;
  event->src_port = src_port;
  event->dst_port = dst_port;
  event->tcp_flags = tcp_flags;
  event->reason = reason;
  event->pad = 0;

  bpf_ringbuf_submit(event, 0);
}

static __always_inline int is_http_port(__u16 dst_port_host) {
  return dst_port_host == 80 || dst_port_host == 443;
}

static __always_inline int is_ip_allowed(__u32 src_ip_host,
                                         __u8 *src_ip_bytes,
                                         struct guard_stats *stats) {
  __u8 *present;
  struct lpm_v4_key key = {.prefixlen = 32, .addr = {0, 0, 0, 0}};

  present = bpf_map_lookup_elem(&http_allow_ips, &src_ip_host);
  if (present) {
    INC_STAT(stats, allowed_by_ip);
    return 1;
  }

  key.addr[0] = src_ip_bytes[0];
  key.addr[1] = src_ip_bytes[1];
  key.addr[2] = src_ip_bytes[2];
  key.addr[3] = src_ip_bytes[3];
  present = bpf_map_lookup_elem(&http_allow_cidrs, &key);
  if (present) {
    INC_STAT(stats, allowed_by_cidr);
    return 1;
  }

  return 0;
}

static __always_inline __u8 evaluate_http_rate_window(
    const struct http_rate_value *value) {
  if (value->syn_count > http_syn_block_threshold)
    return DROP_REASON_HTTP_SYN_RATE;
  if (value->pure_ack_count > http_ack_block_threshold)
    return DROP_REASON_HTTP_ACK_RATE;
  if (value->fin_count > http_fin_block_threshold)
    return DROP_REASON_HTTP_FIN_RATE;
  if (value->packet_count > http_packet_block_threshold)
    return DROP_REASON_HTTP_PACKET_RATE;

  if (value->syn_count > http_syn_limit_per_sec)
    return DROP_REASON_HTTP_SYN_RATE;
  if (value->pure_ack_count > http_ack_limit_per_sec)
    return DROP_REASON_HTTP_ACK_RATE;
  if (value->fin_count > http_fin_limit_per_sec)
    return DROP_REASON_HTTP_FIN_RATE;
  if (value->packet_count > http_packet_limit_per_sec)
    return DROP_REASON_HTTP_PACKET_RATE;

  return DROP_REASON_NONE;
}

static __always_inline __u8 check_http_rate_limit(__u32 src_ip_be,
                                                  __u64 now_ns, int is_syn,
                                                  int is_pure_ack,
                                                  int is_data_ack,
                                                  int is_fin) {
  struct http_rate_value *value;

  value = bpf_map_lookup_elem(&http_rate_map, &src_ip_be);
  if (!value) {
    struct http_rate_value initial = {
        .window_start_ns = now_ns,
        .syn_count = is_syn ? 1 : 0,
        .pure_ack_count = is_pure_ack ? 1 : 0,
        .data_ack_count = is_data_ack ? 1 : 0,
        .fin_count = is_fin ? 1 : 0,
        .packet_count = 1,
        .violations = 0,
    };
    bpf_map_update_elem(&http_rate_map, &src_ip_be, &initial, BPF_ANY);
    return DROP_REASON_NONE;
  }

  if (now_ns - value->window_start_ns >= WINDOW_NS) {
    __u8 prior_reason = evaluate_http_rate_window(value);
    if (prior_reason != DROP_REASON_NONE) {
      value->violations++;
    } else if (value->violations > 0) {
      value->violations--;
    }

    value->window_start_ns = now_ns;
    value->syn_count = is_syn ? 1 : 0;
    value->pure_ack_count = is_pure_ack ? 1 : 0;
    value->data_ack_count = is_data_ack ? 1 : 0;
    value->fin_count = is_fin ? 1 : 0;
    value->packet_count = 1;

    if (prior_reason != DROP_REASON_NONE) {
      return prior_reason;
    } 
    return DROP_REASON_NONE;
  }

  if (is_syn)
    value->syn_count++;
  if (is_pure_ack)
    value->pure_ack_count++;
  if (is_data_ack)
    value->data_ack_count++;
  if (is_fin)
    value->fin_count++;
  value->packet_count++;

  if (value->syn_count > http_syn_block_threshold * 2) {
    value->violations++;
    return DROP_REASON_HTTP_SYN_RATE;
  }
  if (value->pure_ack_count > http_ack_block_threshold * 2) {
    value->violations++;
    return DROP_REASON_HTTP_ACK_RATE;
  }
  if (value->fin_count > http_fin_block_threshold * 2) {
    value->violations++;
    return DROP_REASON_HTTP_FIN_RATE;
  }
  if (value->packet_count > http_packet_block_threshold * 2) {
    value->violations++;
    return DROP_REASON_HTTP_PACKET_RATE;
  }

  if (value->syn_count > http_syn_limit_per_sec * 2)
    return DROP_REASON_HTTP_SYN_RATE;
  if (value->pure_ack_count > http_ack_limit_per_sec * 2)
    return DROP_REASON_HTTP_ACK_RATE;
  if (value->fin_count > http_fin_limit_per_sec * 2)
    return DROP_REASON_HTTP_FIN_RATE;
  if (value->packet_count > http_packet_limit_per_sec * 2)
    return DROP_REASON_HTTP_PACKET_RATE;

  return DROP_REASON_NONE;
}

static __always_inline __u8 check_http_l7_rate(__u32 src_ip_be, __u64 now_ns,
                                               __u32 payload_len) {
  struct http_l7_value *value;

  if (payload_len == 0)
    return DROP_REASON_NONE;

  value = bpf_map_lookup_elem(&http_l7_map, &src_ip_be);
  if (!value) {
    struct http_l7_value initial = {
        .window_start_ns = now_ns,
        .data_packets = 1,
        .violations = 0,
    };
    bpf_map_update_elem(&http_l7_map, &src_ip_be, &initial, BPF_ANY);
    return DROP_REASON_NONE;
  }

  if (now_ns - value->window_start_ns >= WINDOW_NS) {
    __u8 should_drop = DROP_REASON_NONE;

    if (value->data_packets > http_l7_data_block_threshold) {
      value->violations++;
      should_drop = DROP_REASON_HTTP_L7_RATE;
    } else if (value->data_packets > http_l7_data_limit_per_sec) {
      value->violations++;
      should_drop = DROP_REASON_HTTP_L7_RATE;
    } else if (value->violations > 0) {
      value->violations--;
    }

    value->window_start_ns = now_ns;
    value->data_packets = 1;

    return should_drop;
  }

  value->data_packets++;

  if (value->data_packets > http_l7_data_block_threshold * 2) {
    value->violations++;
    return DROP_REASON_HTTP_L7_RATE;
  }
  if (value->data_packets > http_l7_data_limit_per_sec * 2)
    return DROP_REASON_HTTP_L7_RATE;

  return DROP_REASON_NONE;
}

static __always_inline int drop_with_reason(struct guard_stats *stats,
                                            __u8 reason, __u32 src_ip_host,
                                            __u32 dst_ip_host, __u16 src_port,
                                            __u16 dst_port,
                                            __u8 tcp_flags) {
  INC_STAT(stats, dropped_packets);

  switch (reason) {
  case DROP_REASON_SOURCE_NOT_ALLOWED:
    INC_STAT(stats, denied_by_allowlist);
    break;
  case DROP_REASON_HTTP_SYN_RATE:
    INC_STAT(stats, dropped_by_syn_rate);
    break;
  case DROP_REASON_HTTP_ACK_RATE:
    INC_STAT(stats, dropped_by_ack_rate);
    break;
  case DROP_REASON_HTTP_FIN_RATE:
    INC_STAT(stats, dropped_by_fin_rate);
    break;
  case DROP_REASON_HTTP_PACKET_RATE:
    INC_STAT(stats, dropped_by_packet_rate);
    break;
  case DROP_REASON_HTTP_L7_RATE:
    INC_STAT(stats, dropped_by_l7_rate);
    break;
  default:
    break;
  }

  emit_drop_event(reason, src_ip_host, dst_ip_host, src_port, dst_port,
                  tcp_flags);
  return XDP_DROP;
}

SEC("xdp")
int xdp_http_guard(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct guard_stats *stats;
  __u8 *pkt = data;
  __u16 eth_proto;
  __u32 stats_key = 0;
  __u16 dst_port;
  __u16 src_port;
  __u16 total_len;
  __u32 src_ip_host;
  __u32 dst_ip_host;
  __u32 payload_len = 0;
  __u8 tcp_flags;
  __u8 reason;
  __u64 now_ns;
  __u16 frag_off;
  __u8 tcp_doff_raw;
  __u8 tcp_header_len;
  int is_syn;
  int is_pure_ack;
  int is_data_ack;
  int is_fin;

  if (data + MIN_HTTP_FRAME_BYTES > data_end)
    return XDP_PASS;

  eth_proto = ((__u16)pkt[12] << 8) | pkt[13];
  if (eth_proto != ETH_P_IP)
    return XDP_PASS;

  if (pkt[ETH_HLEN_BYTES] != 0x45)
    return XDP_PASS;
  if (pkt[23] != IPPROTO_TCP)
    return XDP_PASS;

  frag_off = ((__u16)pkt[20] << 8) | pkt[21];
  if (frag_off & (IP_FLAG_MF | IP_FRAG_OFFSET_MASK))
    return XDP_PASS;

  dst_port = ((__u16)pkt[36] << 8) | pkt[37];
  if (!is_http_port(dst_port))
    return XDP_PASS;

  stats = bpf_map_lookup_elem(&stats_map, &stats_key);
  INC_STAT(stats, total_packets);

  src_port = ((__u16)pkt[34] << 8) | pkt[35];
  total_len = ((__u16)pkt[16] << 8) | pkt[17];
  dst_ip_host = ((__u32)pkt[30] << 24) | ((__u32)pkt[31] << 16) |
                ((__u32)pkt[32] << 8) | (__u32)pkt[33];
  src_ip_host = ((__u32)pkt[26] << 24) | ((__u32)pkt[27] << 16) |
                ((__u32)pkt[28] << 8) | (__u32)pkt[29];

  if (!is_ip_allowed(src_ip_host, &pkt[26], stats)) {
    tcp_flags = pkt[47];
    return drop_with_reason(stats, DROP_REASON_SOURCE_NOT_ALLOWED,
                            src_ip_host, dst_ip_host, src_port, dst_port,
                            tcp_flags);
  }

  tcp_flags = pkt[47];
  now_ns = bpf_ktime_get_ns();

  tcp_doff_raw = pkt[46] & 0xF0;
  if (tcp_doff_raw < 0x50)
    return XDP_PASS;
  tcp_header_len = tcp_doff_raw >> 2;
  if (total_len > (IPV4_HLEN_BYTES + tcp_header_len))
    payload_len = total_len - (IPV4_HLEN_BYTES + tcp_header_len);

  is_syn = (tcp_flags & TCP_FLAG_SYN) != 0;
  is_pure_ack = ((tcp_flags & TCP_FLAG_ACK) != 0) &&
                ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST |
                               TCP_FLAG_PSH | TCP_FLAG_URG)) == 0) &&
                payload_len == 0;
  is_data_ack = ((tcp_flags & TCP_FLAG_ACK) != 0) && payload_len > 0;
  is_fin = (tcp_flags & TCP_FLAG_FIN) != 0;

  reason = check_http_rate_limit(src_ip_host, now_ns, is_syn, is_pure_ack,
                                 is_data_ack, is_fin);
  if (reason != DROP_REASON_NONE) {
    return drop_with_reason(stats, reason, src_ip_host, dst_ip_host, src_port,
                            dst_port, tcp_flags);
  }

  reason = check_http_l7_rate(src_ip_host, now_ns, payload_len);
  if (reason != DROP_REASON_NONE) {
    return drop_with_reason(stats, reason, src_ip_host, dst_ip_host, src_port,
                            dst_port, tcp_flags);
  }

  INC_STAT(stats, passed_packets);
  return XDP_PASS;
}
