// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES	10240
#define TASK_RUNNING 	0

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 26

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_LATENCY_SLOT + 1);
    __type(key, u32);
    __type(value, u64);
} runq_latency_seconds SEC(".maps");

static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;

	if (!pid)
		return 0;
	if (targ_tgid && targ_tgid != tgid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
	u64 *tsp, slot;
	u32 pid;
	s64 delta;

	if (get_task_state(prev) == TASK_RUNNING)
		trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

	pid = BPF_CORE_READ(next, pid);

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;


	delta = bpf_ktime_get_ns() - *tsp;
	if (delta < 0)
		goto cleanup;
    
    delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_LATENCY_SLOT)
		slot = MAX_LATENCY_SLOT - 1;
	
    increment_map(&runq_latency_seconds, &slot, 1);

    latency_slot = MAX_LATENCY_SLOT + 1;
    increment_map(&runq_latency_seconds, &slot, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
