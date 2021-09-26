from bcc import BPF
from time import sleep

program = """
BPF_HASH(clones);

int hello_world(void *ctx){
  u64 uid;
  u64 counter=0;
  u64 *p;

  uid=bpf_get_current_uid_gid() & 0xFFFFFFFF;
  p=clones.lookup(&uid);

  if(p!=0){
    counter=*p;
  }
  counter++;
  clones.update(&uid,&counter);
  bpf_trace_printk("id:%d\\n",uid);
  return 0;
}
"""

b = BPF(text=program)

clones = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clones, fn_name="hello_world")

while True:
    sleep(2)
    s = ""
    if len(b["clones"].items()):
        for k, v in b["clones"].items():
            s += "ID {}: {}\t".format(k.value, v.value)
        print(s)
    else:
        print("no entries")
