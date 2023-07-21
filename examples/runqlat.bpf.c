// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240
#define MAX_PIDS	1024
#define TASK_RUNNING 	0

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 22

struct pid_latency_key_t {
    u32 pid;
    u64 slot;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u32);
} pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * 128);
    __type(key, struct pid_latency_key_t);
    __type(value, u64);
} runq_latency_seconds SEC(".maps");


static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;
	u64 *count;

	if (!pid)
		return 0;
	count = bpf_map_lookup_elem(&pid_map, &tgid);
	if (!count)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

struct task_struct___o {
	volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x {
	unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct___o *)task, state);
}

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
	u64 *tsp, slot;
	u32 pid, tgid;
	s64 delta;
	u64 *count;
	struct pid_latency_key_t latency_key = {};

	if (get_task_state(prev) == TASK_RUNNING)
		trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

	pid = BPF_CORE_READ(next, pid);
	tgid = BPF_CORE_READ(next, tgid);

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;
	count = bpf_map_lookup_elem(&pid_map, &tgid);
	if (!count)
		return 0;

	delta = bpf_ktime_get_ns() - *tsp;
	if (delta < 0)
		goto cleanup;
    
    delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_LATENCY_SLOT)
		slot = MAX_LATENCY_SLOT - 1;
	
	latency_key.slot = slot;
	latency_key.pid = tgid;

    increment_map(&runq_latency_seconds, &latency_key, 1);

    latency_key.slot = MAX_LATENCY_SLOT + 1;
    increment_map(&runq_latency_seconds, &latency_key, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

// SEC("tp_btf/sched_wakeup")
// int BPF_PROG(sched_wakeup, struct task_struct *p)
// {
// 	return trace_enqueue(p->tgid, p->pid);
// }

// SEC("tp_btf/sched_wakeup_new")
// int BPF_PROG(sched_wakeup_new, struct task_struct *p)
// {
// 	return trace_enqueue(p->tgid, p->pid);
// }

// SEC("tp_btf/sched_switch")
// int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
// {
// 	return handle_switch(preempt, prev, next);
// }

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
