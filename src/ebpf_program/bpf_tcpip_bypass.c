#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h" 
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>
#include "bpf_sockops.h"


static int (*bpf_sys_msleep)(unsigned int mesc) = 
	(void *) BPF_FUNC_sys_msleep;

__section("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg)
{
    struct ip_port dest_key = {};
    struct ip_port src_key = {};
    	
	dest_key.ip4 = msg->remote_ip4;
	dest_key.port = msg->remote_port;

	src_key.ip4 = msg->local_ip4;
	src_key.port = bpf_htonl(msg->local_port);

	printk("sk_msg --- port: %u --> %u", msg->local_port, bpf_ntohl(msg->remote_port) );
	printk("sk_msg --- addr: %x --> %x", bpf_ntohl(msg->local_ip4), bpf_ntohl(msg->remote_ip4) );
    
	// find the fault-injection mode
	int *mode1 = bpf_map_lookup_elem(&svc_ip_hash, &dest_key);	// drop
	int *mode2 = bpf_map_lookup_elem(&svc_ip_hash, &src_key);
	void *data = (void *)(long) msg->data;
	void *data_end = (void *)(long) msg->data_end;
	__u8 *d = data;

	printk("delta=%d", msg->data_end - msg->data);
	printk("data = %x, data_end = %x, length = %d", data, data_end, msg->size);
	printk("protocol = 0x%x", msg->family);

	

	if(mode1){
		int mode1_value = *mode1;
		switch(mode1_value){
			case 3: printk("Drop packet ..."); return SK_DROP;
			case 2: printk("Delay 1s ..."); 
				long start = bpf_ktime_get_ns();
				bpf_sys_msleep(1000);
				long end = bpf_ktime_get_ns();
				printk("start=%lld, end=%lld", start, end);
				break;
			default: break;
		}
		
	}

	if(mode2){
		printk("Modify Return code ...");
		// struct ethhdr *eth = data;
		if(data + sizeof(struct ethhdr) > data_end){
			printk("No ethhdr!");
		}else{
			printk("packet data1: %x, %x, %x", d[0], d[1], d[2]);
			printk("packet data2: %x, %x, %x", d[3], d[4], d[5]);
			printk("packet data3: %x, %x, %x", d[6], d[7], d[8]);
			// 修改返回码为404
			d[9] = 0x34; 
			d[10] = 0x30; 
			d[11] = 0x34; 
		}
	}
	
	return SK_PASS;
}

char ____license[] __section("license") = "GPL";
