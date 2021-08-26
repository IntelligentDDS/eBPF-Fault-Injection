sudo mount -t bpf bpf /sys/fs/bpf/

clang-6.0 -O2 -g -Wall -target bpf -I  /home/kytchett/Documents/linux-5.10.54/include/uapi/linux/ -I /home/kytchett/Documents/linux-5.10.54/tools/lib/bpf/ -c bpf_sockops_v4.c -o bpf_sockops_v4.o

sudo bpftool prog load bpf_sockops_v4.o "/sys/fs/bpf/bpf_sockops"
sudo bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"


sudo bpftool map pin id `sudo bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9,]+' | awk 'BEGIN{FS=","} {print$2}'` "/sys/fs/bpf/sock_ops_map"
# bpftool map pin id `bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9]+' | cut -d ' ' -f2-` "/sys/fs/bpf/sock_ops_map"
# sk_msg
clang-6.0 -O2 -g -Wall -target bpf -I  /home/kytchett/Documents/linux-5.10.54/include/uapi/linux/ -I /home/kytchett/Documents/linux-5.10.54/tools/lib/bpf/ -c bpf_tcpip_bypass.c -o bpf_tcpip_bypass.o

sudo bpftool prog load bpf_tcpip_bypass.o "/sys/fs/bpf/bpf_tcpip_bypass" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map" 
sudo bpftool prog attach pinned "/sys/fs/bpf/bpf_tcpip_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
