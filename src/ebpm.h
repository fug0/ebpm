/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __EBPM_H_
#define __EBPM_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

#ifndef MAX_FUNC_NAME_LEN
#define MAX_FUNC_NAME_LEN 64
#endif

#ifndef OFF_STACK_SAMPLING
#define OFF_STACK_SAMPLING 0
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct task_info {
	pid_t pid;
	pid_t tid;
	__u32 state;
	__u64 cpu_time;
	__u64 vsize;
	__u64 rss;
	char comm[TASK_COMM_LEN];
};

struct stacktrace_event {
	__u32 pid;
	__u32 cpu_id;
	char comm[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
};

#endif /* __EBPM_H_ */
