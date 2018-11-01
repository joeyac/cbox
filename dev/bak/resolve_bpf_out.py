import subprocess

data = open('bpf-hex.out').read().strip().split("\n")

n = len(data)
sock_filter_format = "{{0x{code}, 0x{jt}, 0x{jf}, 0x{k}}},"

# struct sock_filter {	/* Filter block */
# __u16	code;   /* Actual filter code */
# __u8	jt;	/* Jump true */
# __u8	jf;	/* Jump false */
# __u32	k;      /* Generic multiuse field */
# };

out = []
for i in range(n - 1):
    line = data[i]
    item = line.strip().split(" ")
    assert len(item) == 9
    cur1 = sock_filter_format.format(code=item[1], jt=item[2][2:4], jf=item[2][0:2], k=item[4] + item[3])
    cur2 = sock_filter_format.format(code=item[5], jt=item[6][2:4], jf=item[6][0:2], k=item[8] + item[7])
    out.append(cur1)
    out.append(cur2)

with open('bpf-c.out', "w") as f:
    for item in out:
        f.write(item + '\n')
