import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--ips", help="IPv6 destination addresses to drop, separated by commas. A packet with one of the two addresses"
                    "will be dropped")
parser.add_argument("-k", help="Value of K of the markov model", type=int, default=99)
parser.add_argument("-d", help="Value of D of the markov model", type=int, default=2)
parser.add_argument("-f", help="filename to write the compiled eBPF bytecode into (default markov_dropper.o)", default="markov_dropper.o")
parser.add_argument("--attach", help="specifies the interface on whih to attach the generated file", default=None)
parser.add_argument("--attach-ingress", help="if with --attach, dropped will be attach at ingress",
                    action="store_true")
parser.add_argument("--clean", help="clean everything instead of compiling and attaching", action="store_true")
parser.add_argument("--sequence", help="drop a sequence of packets (numbers separated by commas)", default="")

args = parser.parse_args()

sequence = args.sequence
drop_sequence = 1 if sequence else 0

import os

if args.clean:
    if os.path.exists(args.f):
        os.remove(args.f)
    del_dev_cmd = "tc qdisc del dev {} clsact".format(args.attach)
    print(del_dev_cmd)
    os.system(del_dev_cmd)
    exit()

ips = args.ips.split(",")
# "-DIP6_A1_A=0x2042002200000000 -DIP6_A1_B=0x0000000000000002 -DIP6_A2_A=0xfc00000000000000 -DIP6_A2_B=0x0000000000000009 "\
clang_args = "-DIP6_A1_A=0x204200cc00000000 -DIP6_A1_B=0x0000000000000001 -DIP6_A2_A=0xfc00000000000000 -DIP6_A2_B=0x0000000000000009 "\
    "-DSEQUENCE=\\{{{}\\}} -DDROP_SEQUENCE={} "\
    "-DK_MARKOV={} -DD_MARKOV={}".format(sequence, drop_sequence, args.k, args.d)

compile_cmd = "clang -O2 {} -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign " \
                  "-Wno-compare-distinct-pointer-types -I./headers -emit-llvm -c markov_dropper.c -o - | llc -march=bpf " \
                  "-filetype=obj -o {}".format(clang_args, args.f)

os.system(compile_cmd)

if args.attach:
    add_dev_cmd = "tc qdisc replace dev {} clsact".format(args.attach)
    print(add_dev_cmd)
    os.system(add_dev_cmd)
    direction = "ingress" if args.attach_ingress else 'egress'
    attach_cmd = "tc filter replace dev {} {} bpf obj {} section action direct-action"\
        .format(args.attach, direction, args.f)
    print(attach_cmd)
    os.system(attach_cmd)