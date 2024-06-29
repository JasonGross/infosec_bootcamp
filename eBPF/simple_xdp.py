from bcc import BPF

program = """
#include <linux/bpf.h>
#include <linux/if_ether.h>

int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}
"""

b = BPF(text=program)
fn = b.load_func("xdp_pass", BPF.XDP)
b.attach_xdp("eth0", fn, 0)