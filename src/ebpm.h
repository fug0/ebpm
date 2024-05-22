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

#define TASK_COMM_LEN 16
#define MAX_STACK_LEN 127

struct task_info {
	pid_t pid;
	pid_t tid;
	__u32 state;
	char comm[TASK_COMM_LEN];

	int kstack_len;

	__u64 kstack[MAX_STACK_LEN];
};

#endif // EBPM_H
