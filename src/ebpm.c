#include <assert.h>
#include <argp.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpm.skel.h"
#include "ebpm.h"
#include "blazesym.h"

#include "function_hash_table.h"

#define OPT_SYSTEM_PROFILING_MODE   1 /* --profile */

static struct functions_arr {
	uint64_t address;
	uint32_t cpu_id;
	uint32_t count;
    char func_name[64];
};

static struct env {
	bool profiling;
	pid_t pid;
	bool user_stacks_only;
	bool kernel_stacks_only;
	int duration;
	bool verbose;
	bool freq;
	int sample_freq;
} env = {
	.profiling = false,
	.verbose = false,
	.pid = -1,
	.duration = INT_MAX,
	.freq = 1,
	.sample_freq = 49,
};

const char *argp_program_version = "ebpm 0.0.1";
const char *argp_program_bug_address =
	"https://github.com/fug0/ebpm";
const char argp_program_doc[] =
"Observability and Application Performance Montioring tool.\n"
"\n"
// "USAGE: ebpm [OPTIONS...]\n"
"EXAMPLES:\n"
"    ebpm                       # display information about all process currently being managed by the Linux kernel\n"
"    ebpm -v                    # display information about all process but with verbose debug output\n"
"    ebpm --profile 1234        # profile process with PID 1234 stack traces at 49 Hertz until Ctrl-C\n"
"    ebpm --profile 1234 -F 99  # profile stack traces at 99 Hertz until Ctrl-C\n"
"    ebpm --profile 1234 -d 5   # profile at 49 Hertz for 5 seconds only\n"
"    ebpm --profile 1234 -U     # only show user space stacks (no kernel)\n"
"    ebpm --profile 1234 -K     # only show kernel space stacks (no user)\n"
"\nOPTIONS:";

static const struct argp_option opts[] = {
	{ "profile", OPT_SYSTEM_PROFILING_MODE, "PID", 0, "launch utility in profiling mode for profiling process with given PID", 0 },
	{ "user-stacks-only", 'U', NULL, 0, "show stacks from user space only", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0, "show stacks from kernel space only ", 0 },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz", 0 },
	{ "duration", 'd', "DURATION", 0, "profiling duration (in seconds)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
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
	case OPT_SYSTEM_PROFILING_MODE:
		env.profiling = true;
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		fprintf(stderr,
			"Unrecognized positional argument: %s\n", arg);
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
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

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static struct blaze_symbolizer *symbolizer;

static FunctionHashTable *func_table;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // If we have an input address  we have a new symbol.
    if (input_addr != 0) {
      printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf(" %s:%u\n", code_info->file, code_info->line);
      } else {
				printf("\n");
      }
    } else {
      printf("%16s  %s", "", name);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
      } else {
				printf("[inlined]\n");
      }
    }
}

static void handle_stack_trace(__u64 *stack, int stack_sz, pid_t pid, const char *comm, __u32 cpu_id)
{
  	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			function_hash_table_put(func_table, stack[i], "[undefined]", pid, cpu_id, comm);
		}

		sym = &result->syms[i];

		function_hash_table_put(func_table, stack[i], sym->name, pid, cpu_id, comm);

		//print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);
		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			//print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_result_free(result);
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct stacktrace_event *event = data;

	if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
		return 1;

	// printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

	if (event->kstack_sz > 0) {
		handle_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0, event->comm, event->cpu_id);
	}

	if (event->ustack_sz > 0) {
		handle_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid, event->comm, event->cpu_id);
	}

	return 0;
}

static const char *get_task_state(__u32 state)
{
	switch (state) {
		case 0x0000: return "RUNNING";
		case 0x0001: return "INTERRUPTIBLE";
		case 0x0002: return "UNINTERRUPTIBLE";
		case 0x0200: return "WAKING";
		case 0x0400: return "NOLOAD";
		case 0x0402: return "IDLE";
		case 0x0800: return "NEW";
		default: return "<unknown>";
	}
}

int main(int argc, char *const argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	ssize_t ret;
	int i, err = 0;

	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int freq = 1, pid = -1, cpu;
	struct ebpm_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	bool *online_mask = NULL;

	struct task_info buf;
	int iter_fd;

	func_table = create_function_hash_table();

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_stacks_only && env.kernel_stacks_only) {
		fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
		return 1;
	}

	//enable_raw_mode();
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	skel = ebpm_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	if(env.profiling) {
		/* initialize global data (filtering options) */
		skel->rodata->targ_pid = env.pid;
		skel->rodata->user_stacks_only = env.user_stacks_only;
		skel->rodata->kernel_stacks_only = env.kernel_stacks_only;
		skel->rodata->num_cpus = num_cpus;
	}

	err = ebpm_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}

	if(env.profiling) {
		symbolizer = blaze_symbolizer_new();
		if (!symbolizer) {
			fprintf(stderr, "Fail to create a symbolizer\n");
			err = -1;
			goto cleanup;
		}

		/* Prepare ring buffer to receive events from the BPF program. */
		ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
		if (!ring_buf) {
			err = -1;
			goto cleanup;
		}

		pefds = malloc(num_cpus * sizeof(int));
		for (i = 0; i < num_cpus; i++) {
			pefds[i] = -1;
		}

		links = calloc(num_cpus, sizeof(struct bpf_link *));

		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_HARDWARE;
		attr.size = sizeof(attr);
		attr.config = PERF_COUNT_HW_CPU_CYCLES;
		attr.sample_freq = freq;
		attr.freq = 1;

		for (cpu = 0; cpu < num_cpus; cpu++) {
			/* skip offline/not present CPUs */
			if (cpu >= num_online_cpus || !online_mask[cpu])
				continue;

			/* Set up performance monitoring on a CPU/Core */
			pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (pefd < 0) {
				fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
				err = -1;
				goto cleanup;
			}
			pefds[cpu] = pefd;

			/* Attach a BPF program on a CPU */
			links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
			if (!links[cpu]) {
				err = -1;
				goto cleanup;
			}
		}

		if(env.duration < INT_MAX) {
			// Record start time
    		time_t start_time = time(NULL);
			time_t now;

			// Poll ring buffer for the specified duration
			while (!exiting) {
				err = ring_buffer__poll(ring_buf, -1);
				if (err < 0) {
					fprintf(stderr, "Error polling ring buffer: %d\n", err);
					break;
				}

				now = time(NULL);
				if (difftime(now, start_time) >= env.duration) {
					break;
				}
			}
		} else {
			while(!exiting) {
				err = ring_buffer__poll(ring_buf, -1);
				if (err < 0) {
					//fprintf(stderr, "End of ring buffer polling.\n");
					break;
				}
			}
		}

		print_hash_table(func_table);
	} else {
		/* Attach tracepoints */
		err = ebpm_bpf__attach(skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF object\n");
			goto cleanup;
		}

		iter_fd = bpf_iter_create(bpf_link__fd(skel->links.get_tasks));
		if (iter_fd < 0) {
			err = -1;
			fprintf(stderr, "Failed to create iter\n");
			goto cleanup;
		}

		printf("|%-7s|%-7s|%-16s|%-16s|%-16s|%-16s|%-16s\n-------------------------------------------------------------------------------------------\n", 
		"PID", "TID", "NAME", "STATE", "CPU TIME", "VIRT MEM", "RSS MEM");
		while (!exiting) {
			ret = read(iter_fd, &buf, sizeof(struct task_info));
			if (ret < 0) {
				if (errno == EAGAIN)
					continue;
				err = -errno;
				break;
			}
			if (ret == 0)
				break;
			printf("%-7u %-7u %-16s %-16s %-16llu %-16llu %-16llu\n", buf.pid, buf.tid, buf.comm, get_task_state(buf.state), buf.cpu_time, buf.vsize, buf.rss);
		}
	}

cleanup:
	if (links) {
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	if(env.profiling) {
		ring_buffer__free(ring_buf);
		free_function_hash_table(func_table);
		blaze_symbolizer_free(symbolizer);
	} else {
		close(iter_fd);
	}
	ebpm_bpf__destroy(skel);
	free(online_mask);

	return err < 0 ? -err : 0;
}
