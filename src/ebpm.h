/**
 * @file ebpm.h
 * @author Egor Belyaev (eleectricgore@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-05-23
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef EBPM_H
#define EBPM_H

#define TASK_COMM_LEN  16
#define MAX_STACK_LEN  127
#define TASK_COMM_LEN  16
#define MAX_CPU_NR	   128
#define MAX_ENTRIES	   10240

struct task_info {
	pid_t pid;
	pid_t tid;
	__u32 state;
	char comm[TASK_COMM_LEN];

	int kstack_len;

	__u64 kstack[MAX_STACK_LEN];
};

struct key_t {
	__u32 pid;
	int user_stack_id;
	int kern_stack_id;
	char name[TASK_COMM_LEN];
};

#endif // EBPM_H
