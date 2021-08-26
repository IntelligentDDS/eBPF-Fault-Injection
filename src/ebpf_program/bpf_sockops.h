
#ifndef __section
#define __section(NAME) 	\
	__attribute__((section(NAME), used))
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

/* Define fault injection mode */
#define RETURNCODEMODE 	1	// modify HTTP return code
#define DELAYMODE 	2	// request delay
#define TIMEOUTMODE	3 	// request timeout

struct ip_port{
	__u32 ip4;
	__u32 port;
};

struct sock_key {
	__u32 sport;
	__u32 dport;
	__u32 dip4;
	__u32 sip4;
} __attribute__((packed));

// socket needed to be monitored
struct bpf_map_def __section("maps") sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};


struct bpf_map_def __section("maps") svc_ip_hash = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(struct ip_port),	// service served (ip:port)
	.value_size 	= sizeof(int),			// fault-injection mode
	.max_entries 	= 100,
	.map_flags 	= 0,
};
