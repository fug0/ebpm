// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpm.h"

#define PAGE_SHIFT 12

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t targ_pid = -1;
const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile int num_cpus;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct task_info);
} task_info_buf SEC(".maps");

struct task_struct___post514 {
	unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___pre514 {
	long state;
} __attribute__((preserve_access_index));

static __u32 get_task_state(void *arg)
{
	if (bpf_core_field_exists(struct task_struct___pre514, state)) {
		struct task_struct___pre514 *task = arg;

		return task->state;
	} else {
		struct task_struct___post514 *task = arg;

		return task->__state;
	}
}

// Helper function to read percpu_counter
static __always_inline s64 read_percpu_counter(struct percpu_counter *counter) {
    s64 count = 0;
    s64 *counters;
    int i;

    bpf_core_read(&count, sizeof(count), &counter->count);
    bpf_core_read(&counters, sizeof(counters), &counter->counters);

    if (counters) {
        for (i = 0; i < num_cpus; i++) {
            s32 c;
            bpf_core_read(&c, sizeof(c), &counters[i]);
            count += c;
        }
    }

    return count;
}

static __u32 zero = 0;

SEC("iter/task")
int get_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_info *t;
	struct mm_struct *mm;
    struct percpu_counter file_rss;
    struct percpu_counter anon_rss;
	long res;

	if (!task)
		return 1;

	t = bpf_map_lookup_elem(&task_info_buf, &zero);
	if (!t)
		return 1;
		

    // int pid = task->pid;

	// if(tgid != pid) {
	// 	return 1;
	// }

	t->pid = task->tgid;
	t->tid = task->pid;
	// t->pid = task->tgid >> 32;
	// t->tid = task->pid;
	t->state = get_task_state(task);
	t->cpu_time = task->se.sum_exec_runtime;
    t->vsize = task->mm ? task->mm->total_vm << PAGE_SHIFT : 0;	

	mm = BPF_CORE_READ(task, mm);
    if (mm) {
        // Read file and anonymous RSS counters
        BPF_CORE_READ_INTO(&file_rss, mm, rss_stat[MM_FILEPAGES]);
        BPF_CORE_READ_INTO(&anon_rss, mm, rss_stat[MM_ANONPAGES]);

        // Calculate total RSS in bytes
        t->rss = (read_percpu_counter(&file_rss) + read_percpu_counter(&anon_rss)) << PAGE_SHIFT;
	}

    // t->rss = task->mm ? task->mm->rss_stat.count[MM_FILEPAGES].counter + task->mm->rss_stat.count[MM_ANONPAGES].counter : 0;
	// t->cpu_time = BPF_CORE_READ(task, se.sum_exec_runtime);
    // t->vsize = BPF_CORE_READ(task, mm, total_vm) << PAGE_SHIFT;
	// unsigned long file_pages = BPF_CORE_READ(task, mm, rss_stat.count[MM_FILEPAGES].counter);
	// unsigned long anon_pages = BPF_CORE_READ(task, mm, rss_stat.count[MM_ANONPAGES].counter);
    // t->rss = (file_pages + anon_pages) << PAGE_SHIFT;


	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, task->comm);

	bpf_seq_write(seq, t, sizeof(struct task_info));
	return 0;
}

SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *event;
	int cp;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid;
	event->cpu_id = cpu_id;

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;
	
	if(user_stacks_only) {
		event->kstack_sz = OFF_STACK_SAMPLING;
	}
	else
		event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	if(kernel_stacks_only) {
		event->ustack_sz = OFF_STACK_SAMPLING;
	}
	else 
		event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(event, 0);

	return 0;
}
