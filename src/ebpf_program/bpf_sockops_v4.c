#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_sockops.h"


/* update sockhash */ 
static void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops){ 
	struct sock_key key = {};
	
	key.dip4 = skops->remote_ip4;
	key.dport = skops->remote_port;
	key.sip4 = skops->local_ip4;
	key.sport = bpf_htonl(skops->local_port);

	struct ip_port destination = {};
	destination.ip4 = skops->remote_ip4;
	destination.port = skops->remote_port;

	struct ip_port source = {};
	source.ip4 = skops->local_ip4;
	source.port = bpf_htonl(skops->local_port);

	int ret = 0;
	// tracing
	printk("<<< ipv4 op = %d, port %d --> %d from skops",skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	printk("<<< ipv4 op = %d, addr %x --> %x from skops", skops->op, bpf_ntohl(skops->local_ip4), bpf_ntohl(skops->remote_ip4));
	
	// if destination service is in svc_ip_hash
	int *mode1 = bpf_map_lookup_elem(&svc_ip_hash, &destination);
	if (mode1){
		// update sockhash 
		ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);
		if (ret != 0) {
			printk("FAILED: sock_hash_update ret: %d\n", ret);
		}
	}

	// if destination service is in svc_ip_hash
	int *mode2 = bpf_map_lookup_elem(&svc_ip_hash, &source);
	if (mode2){
		// update sockhash 
		ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);
		if (ret != 0) {
			printk("FAILED: sock_hash_update ret: %d\n", ret);
		}
	}
}

__section("sockops")
int bpf_sockops_v4(struct bpf_sock_ops *skops)
{

	int family = skops->family;
	int op = skops->op;

	switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == 2) { //AF_INET
                        bpf_sock_ops_ipv4(skops);
		}
                break;
        default:
                break;
        }
	return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
