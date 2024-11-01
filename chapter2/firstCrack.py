#!/usr/bin/python3  
from bcc import BPF

# Load the eBPF program
bpf_code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <bcc/proto.h>

#define TARGET_IP 0xC0A80001  // Target IP address in hex (example: 192.168.0.1)
#define REDIRECT_IP 0xC0A80002 // Redirect IP address in hex (example: 192.168.0.2)

int redirect_to_ip(struct __sk_buff *skb) {
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    
    // Check if it's an IP packet and if the destination IP matches the target IP
    if (iph->protocol == IPPROTO_TCP && iph->daddr == TARGET_IP) {
        iph->daddr = REDIRECT_IP; // Change the destination IP to the redirect IP
        bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), 0, iph->check, 0);
        return BPF_REDIRECT;
    }
    
    return BPF_PASS;
}
"""
bpf = BPF(text=bpf_code)

# Attach to network device
function_redirect = bpf.load_func("redirect_to_ip", BPF.SCHED_CLS)
bpf.attach_xdp("eth0", function_redirect)

print("eBPF program loaded and running.")
