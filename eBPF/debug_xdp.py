from bcc import BPF

# Load the C program
b = BPF(text=r"""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(blocked_ips, __u32, __u32, 1); // Simplified to just store a single IP

int xdp_prog(struct xdp_md *ctx)
{

    return XDP_DROP;
}

char __license[] __attribute__((section("license"), used)) = "GPL";
""", debug=4)

try:
    fn = b.load_func("xdp_prog", BPF.XDP)
except Exception as e:
    print(f"Error loading BPF program: {e}")
    print(b.get_kprobe_functions(b"xdp"))
    print(b.get_uprobe_functions(b"xdp"))

# Rest of your code...