/**
 * @file ebpm.c
 * @author Egor Belyaev (eleectricgore@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-05-23
 *
 * SPDX-License-Identifier: (Apache License, Version 2.0)
 * @copyright Copyright (c) 2024
 * 
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <asm/unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include "ebpm.h"
#include "ebpm.skel.h"
#include "trace_helpers.h"

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

/*
 * -EFAULT in get_stackid normally means the stack-trace is not available,
 * such as getting kernel stack trace in user mode
 */
#define STACK_ID_EFAULT(stack_id)	(stack_id == -EFAULT)

#define STACK_ID_ERR(stack_id)		((stack_id < 0) && !STACK_ID_EFAULT(stack_id))

/* hash collision (-EEXIST) suggests that stack map size may be too small */
#define CHECK_STACK_COLLISION(ustack_id, kstack_id)	\
	(kstack_id == -EEXIST || ustack_id == -EEXIST)

#define MISSING_STACKS(ustack_id, kstack_id)	\
	(!env.user_stacks_only && STACK_ID_ERR(kstack_id)) + (!env.kernel_stacks_only && STACK_ID_ERR(ustack_id))

/* This structure combines key_t and count which should be sorted together */
struct key_ext_t {
	struct key_t k;
	__u64 v;
};

typedef const char* (*symname_fn_t)(unsigned long);

static struct env {
	bool system_wide;
	pid_t pid;
	pid_t tid;
	bool user_stacks_only;
	bool kernel_stacks_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	bool verbose;
	bool freq;
	int sample_freq;
	bool include_idle;
	int cpu;
} env = {
	.system_wide = false,
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
};

const char *argp_program_version = "ebpm 0.1";
const char *argp_program_bug_address =
	"https://github.com/fug0/ebpm";
const char argp_program_doc[] =
"Write program doc.\n"
"\n"
"USAGE: ebpm [OPTIONS...] [duration]\n"
"EXAMPLES:\n";

static const struct argp_option opts[] = {
	{ "system-wide", 's', NULL, 0, "show system-wide performance analysis (for every running process)" },
	{ "pid", 'p', "PID", 0, "profile process with this PID only" },
	{ "tid", 'L', "TID", 0, "profile thread with this TID only" },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)" },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)" },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz" },
	{ "include-idle ", 'I', NULL, 0, "include CPU idle stacks" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

struct ksyms *ksyms;
struct syms_cache *syms_cache;
struct syms *syms;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 's':
		env.system_wide = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'L':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
		break;
	case 'F':
		errno = 0;
		env.sample_freq = strtol(arg, NULL, 10);
		if (errno || env.sample_freq <= 0) {
			fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'I':
		env.include_idle = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = env.freq,
		.sample_freq = env.sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		if (env.cpu != -1 && env.cpu != i)
			continue;

		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}


static int cmp_counts(const void *a, const void *b)
{
	const __u64 x = ((struct key_ext_t *) a)->v;
	const __u64 y = ((struct key_ext_t *) b)->v;

	/* descending order */
	return y - x;
}

static int read_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
	struct key_t empty = {};
	struct key_t *lookup_key = &empty;
	int i = 0;
	int err;

	while (bpf_map_get_next_key(fd, lookup_key, &items[i].k) == 0) {
		err = bpf_map_lookup_elem(fd, &items[i].k, &items[i].v);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			return -err;
		}

		if (items[i].v == 0)
			continue;

		lookup_key = &items[i].k;
		i++;
	}

	*count = i;
	return 0;
}

static const char *ksymname(unsigned long addr)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, addr);

	return ksym ? ksym->name : "[unknown]";
}

static const char *usymname(unsigned long addr)
{
	const struct sym *sym = syms__map_addr(syms, addr);

	return sym ? sym->name : "[unknown]";
}

static void print_stacktrace(unsigned long *ip, symname_fn_t symname)
{
	for (size_t i = 0; ip[i] && i < env.perf_max_stack_depth; i++)
		printf("    %s\n", symname(ip[i]));
}

static int print_count(struct key_t *event, __u64 count, int stack_map)
{
	unsigned long *ip;

	ip = calloc(env.perf_max_stack_depth, sizeof(unsigned long));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return -ENOMEM;
	}

	/* kernel stack */
	if (!env.user_stacks_only && !STACK_ID_EFAULT(event->kern_stack_id)) {
		if (bpf_map_lookup_elem(stack_map, &event->kern_stack_id, ip) != 0)
			printf("    [Missed Kernel Stack]\n");
		else
			print_stacktrace(ip, ksymname);
	}

	/* user stack */
	if (!env.kernel_stacks_only && !STACK_ID_EFAULT(event->user_stack_id)) {
		if (bpf_map_lookup_elem(stack_map, &event->user_stack_id, ip) != 0) {
			printf("    [Missed User Stack]\n");
		} else {
			syms = syms_cache__get_syms(syms_cache, event->pid);
			if (!syms)
				fprintf(stderr, "failed to get syms\n");
			else
				print_stacktrace(ip, usymname);
		}
	}

	/* process information */
	printf("    %-16s %s (%d)\n", "-", event->name, event->pid);

	/* count sampled */
	printf("        %lld\n\n", count);

	free(ip);

	return 0;
}

static int print_counts(int counts_map, int stack_map)
{
	struct key_ext_t *counts;
	struct key_t *event;
	__u64 count;
	__u32 nr_count = MAX_ENTRIES;
	size_t nr_missing_stacks = 0;
	bool has_collision = false;
	int i, ret = 0;

	counts = calloc(MAX_ENTRIES, sizeof(struct key_ext_t));
	if (!counts) {
		fprintf(stderr, "Out of memory\n");
		return -ENOMEM;
	}

	ret = read_counts_map(counts_map, counts, &nr_count);
	if (ret)
		goto cleanup;

	qsort(counts, nr_count, sizeof(struct key_ext_t), cmp_counts);

	for (i = 0; i < nr_count; i++) {
		event = &counts[i].k;
		count = counts[i].v;

		print_count(event, count, stack_map);

		/* handle stack id errors */
		nr_missing_stacks += MISSING_STACKS(event->user_stack_id, event->kern_stack_id);
		has_collision = CHECK_STACK_COLLISION(event->user_stack_id, event->kern_stack_id);
	}

	if (nr_missing_stacks > 0) {
		fprintf(stderr, "WARNING: %zu stack traces could not be displayed.%s\n",
			nr_missing_stacks, has_collision ?
			" Consider increasing --stack-storage-size.":"");
	}

cleanup:
	free(counts);

	return ret;
}

static void print_headers()
{
	printf("Sampling at %d Hertz of", env.sample_freq);

	if (env.pid != -1)
		printf(" PID %d", env.pid);
	else if (env.tid != -1)
		printf(" TID %d", env.tid);
	else
		printf(" all threads");

	if (env.user_stacks_only)
		printf(" by user");
	else if (env.kernel_stacks_only)
		printf(" by kernel");
	else
		printf(" by user + kernel");

	if (env.cpu != -1)
		printf(" on CPU#%d", env.cpu);

	printf("... Hit Ctrl-C to end.\n");
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static const char *get_task_state(__u32 state)
{
	/* Taken from:
	 * https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L85
	 * There are a lot more states not covered here but these are common ones.
	 */
	switch (state) {
	case 0x0000:
		return "RUNNING";
	case 0x0001:
		return "INTERRUPTIBLE";
	case 0x0002:
		return "UNINTERRUPTIBLE";
	case 0x0200:
		return "WAKING";
	case 0x0400:
		return "NOLOAD";
	case 0x0402:
		return "IDLE";
	case 0x0800:
		return "NEW";
	default:
		return "<unknown>";
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct ebpm_bpf *skel;
	struct task_info buf;
	int iter_fd;
	ssize_t ret;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_stacks_only && env.kernel_stacks_only) {
		fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
		return 1;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open, load, and verify BPF application */
	skel = ebpm_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	if(!env.system_wide) {
		/* initialize global data (filtering options) */
		skel->rodata->targ_pid = env.pid;
		skel->rodata->targ_tid = env.tid;
		skel->rodata->user_stacks_only = env.user_stacks_only;
		skel->rodata->kernel_stacks_only = env.kernel_stacks_only;
		skel->rodata->include_idle = env.include_idle;
	}

	bpf_map__set_value_size(skel->maps.stackmap,
			env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stackmap, env.stack_storage_size);

	err = ebpm_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}

	if(!env.system_wide) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "failed to load kallsyms\n");
			goto cleanup;
		}

		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			fprintf(stderr, "failed to create syms_cache\n");
			goto cleanup;
		}

		err = open_and_attach_perf_event(env.freq, skel->progs.do_perf_event, links);
		if (err)
			goto cleanup;

		print_headers();

		sleep(5);

		print_counts(bpf_map__fd(skel->maps.counts),
		     		 bpf_map__fd(skel->maps.stackmap));
	} else {
		/* Attach tracepoints */
		err = ebpm_bpf__attach(skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto cleanup;
		}

		iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_tasks));
		if (iter_fd < 0) {
			err = -1;
			fprintf(stderr, "Failed to create iter\n");
			goto cleanup;
		}

		while (true) {
			ret = read(iter_fd, &buf, sizeof(struct task_info));
			if (ret < 0) {
				if (errno == EAGAIN)
					continue;
				err = -errno;
				break;
			}
			if (ret == 0)
				break;
			if (buf.kstack_len <= 0) {
				printf("Error getting kernel stack for task. Task Info. Pid: %d. Process Name: %s. Kernel Stack Error: %d. State: %s\n",
					buf.pid, buf.comm, buf.kstack_len, get_task_state(buf.state));
			} else {
				printf("Task Info. Pid: %d. Process Name: %s. Kernel Stack Len: %d. State: %s\n",
					buf.pid, buf.comm, buf.kstack_len, get_task_state(buf.state));
			}
		}
	}

cleanup:
	/* Clean up */
	if (env.cpu != -1)
		bpf_link__destroy(links[env.cpu]);
	else {
		for (i = 0; i < nr_cpus; i++)
			bpf_link__destroy(links[i]);
	}
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (ksyms)
		ksyms__free(ksyms);

	close(iter_fd);
	ebpm_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
