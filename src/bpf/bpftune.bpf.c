// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "bpftune.h"

// dummy for generating types
struct stacktrace_event _event = {0};
struct eth_event _eth_event = {0};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} eth_events SEC(".maps");


SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *event;
	int cp;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid;
	event->cpu_id = cpu_id;

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

static inline int get_tcp_dest_port(void *data, u64 nh_off, void *data_end) {
    struct tcphdr *tcph = data + nh_off;

    if (data + nh_off + sizeof(struct tcphdr) > data_end)
        return 0;
    return tcph->dest;
}

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if (data + nh_off + sizeof(struct iphdr) > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if (data + nh_off + sizeof(struct ipv6hdr) > data_end)
        return 0;
    return ip6h->nexthdr;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	const int l3_off = 14 /*ETH_HLEN*/;                // IP header offset
	const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
	const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP) header offset
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	if (data_end < data + l7_off) {
		return XDP_PASS;
	}
	struct ethhdr *eth = data;

	uint16_t h_proto;
	uint64_t nh_off = 0;
	uint16_t dest_port;
	uint32_t index;

	h_proto = eth->h_proto;
	if (h_proto == __bpf_htons(0x0800 /*ETH_P_IP*/)) {
		h_proto = parse_ipv4(data, nh_off, data_end);
		nh_off += sizeof(struct iphdr);
	} else if (h_proto == __bpf_htons(0x86DD /*ETH_P_IPV6*/)) {
		h_proto = parse_ipv6(data, nh_off, data_end);
		nh_off += sizeof(struct ipv6hdr);
	} else {
		return XDP_PASS;
	}

	struct eth_event *event;
	event = bpf_ringbuf_reserve(&eth_events, sizeof(*event), 0);
	if (!event) {
		return XDP_PASS;
	}
	event->proto = h_proto;
	if (h_proto == IPPROTO_TCP) {
		struct tcphdr *tcph = data + nh_off;
		event->port = __bpf_ntohs(get_tcp_dest_port(data, nh_off, data_end));
		event->saddr = tcph->source;
		event->daddr = tcph->dest;
		event->seq = tcph->seq;
	} else if (h_proto == IPPROTO_UDP) {
		struct udphdr *udph = data + nh_off;
		event->saddr = udph->source;
		event->daddr = udph->dest;
	}

	bpf_ringbuf_submit(event, 0);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
