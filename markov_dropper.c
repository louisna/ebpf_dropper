#define KBUILD_MODNAME "EBPF Dropper"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define ETH_HLEN 14

#ifndef DROP_SEQUENCE
#define SEQUENCE {}
#define DROP_SEQUENCE 0
#endif

#ifndef DROP_UNIFORM
#define DROP_UNIFORM 0
#endif

#ifndef SEQUENCE
#define SEQUENCE {0, 3, 8, 10, 4}
#endif

// from uapi/linux/pkt_cls.h
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

#define PASS TC_ACT_OK
#define DROP TC_ACT_SHOT

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
			})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

struct ip6_t {
  __u32        ver:4;
  __u32        priority:8;
  __u32        flow_label:20;
  __u16      payload_len;
  __u8       next_header;
  __u8       hop_limit;
  __u64  src_hi;
  __u64  src_lo;
  __u64  dst_hi;
  __u64  dst_lo;
} __attribute__((packed));

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

typedef struct {
    __u64 ip6_a;
    __u64 ip6_b;
} my_ipv6_t;

typedef struct {
    __u16 k;
    __u16 d;
    __u16 u;
    __u8 current_state;
    __u64 seed;
    __u32 intercepted;
    __u64 bytes_received;
} drop_markov_t;

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};
//


struct bpf_elf_map SEC("maps") interceptionMap = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(int),
        .size_value = sizeof(drop_markov_t),
        .pinning = 0,
        .max_elem = 1,
};

// From https://stackoverflow.com/questions/506118/how-to-manually-generate-random-numbers
static __always_inline __u64 my_random_generator(__u64 seed) {
    __u64 next = seed * 1103515245 + 12345;
    return ((unsigned) (next / 65536) % 32768);
}

// returns the dest port as a 16 bits unsigned integer
__attribute__((always_inline)) __u16 get_udp_dport(struct __sk_buff *skb) {
    ////// LOAD DEST PORT BYTE PER BYTE
    __u16 b1 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct ip6_t) + offsetof(struct udphdr, dest)) << 8);
    __u16 b2 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct ip6_t) + offsetof(struct udphdr, dest) + 1));
    ////// END LOAD DEST PORT BYTE PER BYTE
    return (b1 + b2);
}

// returns the dest port as a 16 bits unsigned integer
__attribute__((always_inline)) __u16 get_udp_sport(struct __sk_buff *skb) {
    ////// LOAD SOURCE PORT BYTE PER BYTE
    __u16 b1 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct ip6_t) + offsetof(struct udphdr, source)) << 8);
    __u16 b2 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct ip6_t) + offsetof(struct udphdr, source) + 1));
    ////// END LOAD SOURCE PORT BYTE PER BYTE
    return (b1 + b2);
}

__attribute__((always_inline)) int notify_if_port(struct __sk_buff *skb, __u16 port) {
    __u16 sport;
    __u16 dport;
    sport = get_udp_sport(skb);
    dport = get_udp_dport(skb);

    return (port == sport || port == dport) ? 1 : 0;
}

__attribute__((always_inline)) void set_saddr_ipv6(struct __sk_buff *skb, my_ipv6_t *addr) {
    struct ip6_t *iphdr = (struct ip6_t *) skb + ETH_HLEN;
    // Load IPv6 byte per byte
    __u64 a1 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi)) << 56;
    __u64 a2 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 1) << 48;
    __u64 a3 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 2) << 40;
    __u64 a4 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 3) << 32;
    __u64 a5 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 4) << 24;
    __u64 a6 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 5) << 16;
    __u64 a7 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 6) << 8;
    __u64 a8 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_hi) + 7);
    addr->ip6_a = a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;

    a1 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo)) << 56;
    a2 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 1) << 48;
    a3 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 2) << 40;
    a4 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 3) << 32;
    a5 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 4) << 24;
    a6 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 5) << 16;
    a7 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 6) << 8;
    a8 = load_byte(skb, ETH_HLEN + offsetof(struct ip6_t, src_lo) + 7);
    addr->ip6_b = a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;
}

__attribute__((always_inline)) void set_daddr_ipv6(struct __sk_buff *skb, my_ipv6_t *addr) {
    struct ip6_t *iphdr = (struct ip6_t *) skb + ETH_HLEN;
    __u64 a = load_byte(skb, ETH_HLEN + 8 + 16);
    // Load IPv6 byte per byte
    __u64 a1 = load_byte(skb, ETH_HLEN + 8 + 16) << 56;
    __u64 a2 = load_byte(skb, ETH_HLEN + 8 + 16 + 1) << 48;
    __u64 a3 = load_byte(skb, ETH_HLEN + 8 + 16 + 2) << 40;
    __u64 a4 = load_byte(skb, ETH_HLEN + 8 + 16 + 3) << 32;
    __u64 a5 = load_byte(skb, ETH_HLEN + 8 + 16 + 4) << 24;
    __u64 a6 = load_byte(skb, ETH_HLEN + 8 + 16 + 5) << 16;
    __u64 a7 = load_byte(skb, ETH_HLEN + 8 + 16 + 6) << 8;
    __u64 a8 = load_byte(skb, ETH_HLEN + 8 + 16 + 7);
    addr->ip6_a = a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;

    a1 = load_byte(skb, ETH_HLEN + 8 + 16 + 8) << 56;
    a2 = load_byte(skb, ETH_HLEN + 8 + 16 + 9) << 48;
    a3 = load_byte(skb, ETH_HLEN + 8 + 16 + 10) << 40;
    a4 = load_byte(skb, ETH_HLEN + 8 + 16 + 11) << 32;
    a5 = load_byte(skb, ETH_HLEN + 8 + 16 + 12) << 24;
    a6 = load_byte(skb, ETH_HLEN + 8 + 16 + 13) << 16;
    a7 = load_byte(skb, ETH_HLEN + 8 + 16 + 14) << 8;
    a8 = load_byte(skb, ETH_HLEN + 8 + 16 + 15);
    addr->ip6_b = a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;
}

__attribute__((always_inline)) int drop_if_addrs_ipv6(struct __sk_buff *skb, my_ipv6_t *addr1, my_ipv6_t *addr2) {
    my_ipv6_t dst;
    set_daddr_ipv6(skb, &dst);
    __u8 found = 0;

    // Check first
    //bpf_debug("--1==%u et 1==%u\n", dst.ip6_a == addr1->ip6_a, dst.ip6_b == addr1->ip6_b);
    //bpf_debug("1==%u et 1==%u\n", dst.ip6_a == addr2->ip6_a, dst.ip6_b == addr2->ip6_b);
    //bpf_debug("En hexadecimal je cherche: %llx %llx\n", addr1->ip6_a, addr1->ip6_b);
    //bpf_debug("Et j'ai: %llx %llx\n", dst.ip6_a, dst.ip6_b);
    if (dst.ip6_a == addr1->ip6_a && dst.ip6_b == addr1->ip6_b) return 1;
    if (dst.ip6_a == addr2->ip6_a && dst.ip6_b == addr2->ip6_b) return 1;

    return 0;
}

__attribute__((always_inline)) void update_markov_model(drop_markov_t *markov) {
    markov->bytes_received = 0;
    markov->intercepted = 0;
    markov->seed = 42;
    if (markov->d >= 500) {
        markov->d = 0;
        markov->k -= 10;
    } else {
        markov->d += 20;
    }

    if (markov->k < 900) {
        markov->k = 900;
        bpf_debug("Droper: /!\\ already in this state\n");
    }
    bpf_debug("Droper: updated the params to k=%d, d=%d\n", markov->k, markov->d);
}

__attribute__((always_inline)) void update_markov_model_only_k(drop_markov_t *markov) {
    markov->bytes_received = 0;
    //bpf_debug("Intercepted=%u\n", markov->intercepted);
    markov->intercepted = 1;
    markov->k -= 5;

    if (markov->k < 900) {
        markov->k = 900;
        bpf_debug("Droper: /!\\ already in this state\n");
    }
    bpf_debug("Droper: updated the params to k=%d, d=%d\n", markov->k, markov->d);
}

__attribute__((always_inline)) void update_markov_model_defined(drop_markov_t *markov) {
    markov->bytes_received = 0;
    markov->intercepted = 1;
    if (markov->d >= 500) {
        markov->d = 0;
        if (markov->k == 990) {
            markov->k = 960;
        } else if (markov->k == 960) {
            markov->k = 930;
        } else if (markov->k == 930) {
            markov->k = 900;
        } else {
            bpf_debug("Droper: /!\\ Already in this state");
        }
    } else {
        markov->d += 20;
    }
    bpf_debug("Droper: updated the params to k=%d, d=%d\n", markov->k, markov->d);
}

__attribute__((always_inline)) int update_uniform_model(drop_markov_t *markov) {
    markov->bytes_received = 0;
    markov->intercepted = 1;
    markov->u += 5;

    if (markov->u > 150) {
        markov->u = 150;
        bpf_debug("Droper: /!\\ already in this state\n");
    }
    bpf_debug("Droper: updated the params of uniform to u=%u\n", markov->u);
    return 0;
}

__attribute__((always_inline)) int update_model_notify(struct __sk_buff *skb) {
    if (notify_if_port(skb, 3333)) return 1;
    return 0;
}

__attribute__((always_inline)) int drop_markov_model(struct __sk_buff *skb) {
    int k = 0;
    drop_markov_t *markov = bpf_map_lookup_elem(&interceptionMap, &k);
    if (!markov) return PASS;

    if (markov->k == 0) {
        markov->k = K_MARKOV;
        markov->d = D_MARKOV;
        markov->seed = 42;
        markov->bytes_received = 0;
    }

    // Add the number of bytes of this packet to the total (removing the ETHERNET header)
    //if (notify_if_port(skb, 1883))
    markov->bytes_received += skb->len - 14;
    /* Update the intercepted value */
    ++markov->intercepted;

    if (notify_if_port(skb, 3333)) {
        // Before updating, indicate the number of bytes received for this test
        bpf_debug("Total received: %llu\n", markov->bytes_received);
        update_markov_model(markov);
        return DROP;
    } else if (notify_if_port(skb, 3334)) {
        bpf_debug("Total received packets: %u bytes: %u\n", markov->intercepted, markov->bytes_received);
        markov->bytes_received = 0;
        markov->intercepted = 0;
        markov->seed = 0;
    }

    int is_to_drop = 0;
    __u64 next = my_random_generator(markov->seed);


    /* The current value will serve as the seed for next call */
    markov->seed = next;

    /* Update the finite state machine */
    if (markov->current_state == 0) { // PASS state
        if (next % 1000 < markov->k) { // Keep the symbol
            markov->current_state = 0;
            return PASS;
        } else {
            markov->current_state = 1;
            //bpf_debug("Drop intercepted #%d\n", markov->intercepted - 1);
            return DROP;
        }
    } else {
        if (next % 1000 >= markov->d) { // Keep the symbol
            markov->current_state = 0;
            return PASS;
        } else {
            markov->current_state = 1;
            //bpf_debug("Drop intercepted #%d\n", markov->intercepted - 1);
            return DROP;
        }
    }
}

__attribute__((always_inline)) int drop_uniform(struct __sk_buff *skb) {
    int k = 0;
    drop_markov_t *markov = bpf_map_lookup_elem(&interceptionMap, &k);
    if (!markov) return PASS;

    if (markov->intercepted == 0) {
        markov->seed = 42;
        markov->u = U_UNIFORM;
        markov->bytes_received = 0;
    }

    // Add the number of bytes of this packet to the total (removing the ETHERNET header)
    markov->bytes_received += skb->len - 14;
    
    if (notify_if_port(skb, 3333)) {
        // Before updating, indicate the number of bytes received for this test
        bpf_debug("Total received: %llu\n", markov->bytes_received);
        update_uniform_model(markov);
        return DROP;
    } else if (notify_if_port(skb, 3334)) {
        bpf_debug("Total received packets: %u bytes: %u\n", markov->intercepted, markov->bytes_received);
        markov->bytes_received = 0;
        markov->intercepted = 0;
        markov->seed = 0;
    }

    int is_to_drop = 0;
    __u64 next = my_random_generator(markov->seed);

    /* Update the intercepted value */
    ++markov->intercepted;

    /* The current value will serve as the seed for next call */
    markov->seed = next;

    if (next % 1000 <= markov->u) {
        //bpf_debug("Drop uniform packete\n");
        return DROP;
    }
    return PASS;
}

__attribute__((always_inline)) int drop_sequence(__u32 sequence[], uint8_t len) {
    int k = 0;

    drop_markov_t *intercepted = bpf_map_lookup_elem(&interceptionMap, &k);
    if (!intercepted) return PASS;

    int is_to_drop = 0;
    for (int i = 0; i < len; ++i) {
        if (intercepted->intercepted == sequence[i]) {
            is_to_drop = 1;
            break;
        }
    }

    //bpf_printk("Drop: I drop ? %d with value %d\n", is_to_drop, intercepted->intercepted);
    
    if (is_to_drop) {
        //bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, intercepted, sizeof(int));
        intercepted->intercepted += 1;
        bpf_debug("Drop packet %u\n", intercepted->intercepted-1);
        return DROP;
    } else {
        intercepted->intercepted += 1;
        return PASS;
    }
}

__attribute__((always_inline)) int my_decision_function(struct __sk_buff *skb) {
    my_ipv6_t src = {
        .ip6_a = IP6_A1_A,
        .ip6_b = IP6_A1_B,
    };
    my_ipv6_t dst = {
        .ip6_a = IP6_A2_A,
        .ip6_b = IP6_A2_B,
    };
    if (drop_if_addrs_ipv6(skb, &src, &dst)) {
        #if DROP_SEQUENCE
         __u32 sequence[] = SEQUENCE;
        return drop_sequence(sequence, sizeof(sequence) / sizeof(__u32));
        #elif DROP_UNIFORM
        return drop_uniform(skb);
        #else
        return drop_markov_model(skb);
        #endif
    }
    return PASS;
}

SEC("action") int handle_ingress(struct __sk_buff *skb)
{
    return my_decision_function(skb);
}

char _license[] SEC("license") = "GPL";