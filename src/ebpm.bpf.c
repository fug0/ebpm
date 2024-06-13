/**
 * @file ebpm.bpf.c
 * @author Egor Belyaev (eleectricgore@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-05-23
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ebpm.h"
#include "maps.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile pid_t targ_pid = -1;
const volatile pid_t targ_tid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

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

static __u32 zero = 0;

SEC("iter/task")
int get_tasks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_info *t;
	long res;

	if (!task)
		return 0;

	t = bpf_map_lookup_elem(&task_info_buf, &zero);
	if (!t)
		return 0;

	t->pid = task->tgid;
	t->tid = task->pid;
	t->state = get_task_state(task);

	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, task->comm);

	res = bpf_get_task_stack(task, t->kstack, sizeof(__u64) * MAX_STACK_LEN, 0);
	t->kstack_len = res <= 0 ? res : res / sizeof(t->kstack[0]);

	bpf_seq_write(seq, t, sizeof(struct task_info));
	return 0;
}

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = id;
	u64 *valp;
	static const u64 zero;
	struct key_t key = {};

	if (!include_idle && tid == 0)
		return 0;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;

	if (targ_tid != -1 && targ_tid != tid)
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only)
		key.kern_stack_id = -1;
	else
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);

	if (kernel_stacks_only)
		key.user_stack_id = -1;
	else
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap,
						    BPF_F_USER_STACK);

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	return 0;
}