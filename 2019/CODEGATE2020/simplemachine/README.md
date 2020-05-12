# Simple machine

This is rev challenge that implements literally simple machine.

Challenge includes binary implementing machine, and instruction data.
```
00000000: 0624 0000 0040 2400 0129 0040 0040 bdb0  .$...@$..).@.@..
00000010: 0444 0100 0000 0040 0520 0000 0100 a001  .D.....@. ......
00000020: 0129 0240 0240 bcba 0444 0100 0000 0240  .).@.@...D.....@
00000030: 0520 0000 0100 a001 0129 0440 0440 b9be  . .......).@.@..
00000040: 0444 0100 0000 0440 0520 0000 0100 a001  .D.....@. ......
00000050: 0129 0640 0640 acba 0444 0100 0000 0640  .).@.@...D.....@
00000060: 0520 0000 0100 a001 0129 0840 0840 cecf  . .......).@.@..
...
```

Let's look at binary. main function is as follows.

main function initializes context which contains state info of machine.
```
int main(int argc, char **argv)
{
  // ...
  context = (Context *)operator new(0x48uLL);
  initialize_context(context, (const void **)&file_addr_ptr);

  while ( keep_running(context) )
    evaluate(context);

  // ...
}
```

Here is structure of context.
```
struct Context {
    buffer: u64,
    buffer_end: u64,
    buffer_end_: u64,
    keep_running: u32,
    rax_cache: u16[3],
    pc: u16,
    inst_low0: u8,
    inst_low7: u8,
    inst_low10: u8,
    inst_low13: u8,
    operand_1: u32,
    operand_2: u32,
    operand_3: u32,
    mem_fetch: u8,
    dummy: u8,
    opcode: u8,
    inst_low7_: u8,
    operand_1_: u32,
    reg_1: u32,
    reg_2: u32,
    is_executable: u8,
    dummy: u8,
    inst_low7__: u8,
    dummy: u8,
    operand_1__: u32,
    rax_: u32,
    full_pipeline: u8,
    dummy: u8,
    dummy: u8,
    dummy: u8,
    dummy: u8,
    dummy: u8,
    dummy: u8,
    dummy: u8,
}
```

execute() is as follows.

Overall implementation is based on pipeline architecture.

Without computer architecture knowledge, it would've been difficult to understand context of code.
```
void evaluate(Context *context)
{
  mem_write_back(context);
  if ( context->is_executable )
    execute(context);
  if ( context->mem_fetch )
    mem_fetch(context);
  inst_fetch(context);
}
```

I took a look at inst_fetch().

```
void inst_fetch(Context *context)
{
  // variable declarations

  instruction = get_value(context, context->pc);
  context->inst_low0 = instruction & 0x7F;
  context->inst_low7 = (instruction >> 7) & 7;
  context->inst_low10 = (instruction >> 10) & 7;
  context->inst_low13 = (instruction >> 13) & 7;
  
  pc = context->pc;

  context->operand_1 = get_value(context, pc_ + 2);
  context->operand_2 = get_value(context, context->pc + 4);
  context->operand_3 = get_value(context, context->pc + 6);

  context->mem_fetch = 1;
  context->pc += 8;
}
```

The machine uses 8-byte instruction,

and has program counter, three registers(two of them for calculation, one for result)

inst_fecth() reads two bytes and stores it in little endian order.

instruction has four parts:
- instruction parts(2 bytes)
- operand 1(2 bytes)
- operand 2(2 bytes)
- operand 3(2 bytes)

and instruction parts consists of 4 parts.
- reg_2_type: decides whether uses immediate value or value in memory for register 2
- reg_1_type: decides whether uses immediate value or value in memory for register 1
- mem_write: decides whether machine stores values in memory
- opcode: decides which operation machine executes
  - 0: mov
  - 1: add
  - 2: mul
  - 3: xor
  - 4: cmp
  - 5: branch
  - 6: read (register 2) bytes and stores them in buffer pointed by register 1
  - 7: write (register 2) bytes to stdout
  - 8: terminate machine
```
+----------------------------------------------------------------------------------+
|  reg_2_type(3-bit)  |  reg_1_type(3-bit)  |  mem_write(3-bit)  |  opcode(7-bit)  |
+----------------------------------------------------------------------------------+
```

mem_fetch() considers several forwarding logic of pipeline.

Logic is very complicated, and in fact is not needed to be reverse engineered.

What are important are values fetched to registers.

It's enough to break on execute() and what values are used and what operation is executed.

```
void execute(Context *context)
{
  // variable declarations

  switch ( (unsigned __int64)context->opcode )
  {
    case 0uLL:                                  // mov
      context->rax_ = context->reg_1;
      goto LABEL_3;
    case 1uLL:                                  // add
      context->rax_ = context->reg_1 + context->reg_2;
      goto LABEL_3;
    case 2uLL:                                  // mul
      context->rax_ = context->reg_2 * context->reg_1;
      goto LABEL_3;
    case 3uLL:                                  // xor
      context->rax_ = context->reg_2 ^ context->reg_1;
      goto LABEL_3;
    case 4uLL:                                  // cmp
      context->rax_ = context->reg_1 < context->reg_2;
      goto LABEL_3;
    case 5uLL:                                  // branch
      if ( !context->reg_1 )
        goto LABEL_3;
      v2 = context->reg_2;
      context->mem_fetch = 0;
      context->is_executable = 0;
      context->full_pipeline = 0;
      context->pc = v2;
      break;
    case 6uLL:                                  // read
      context->rax_ = read_(context, context->reg_1, context->reg_2);
      goto LABEL_3;
    case 7uLL:                                  // write
      context->rax_ = write(1, (const void *)(context->buffer + context->reg_1), context->reg_2);
      goto LABEL_3;
    case 8uLL:                                  // terminate
      context->mem_fetch = 0;
      context->is_executable = 0;
      context->full_pipeline = 0;
      context->keep_running = 0;
      return;
    default:
LABEL_3:
      inst_low7_ = context->inst_low7_;
      context->full_pipeline = 1;
      context->inst_low7__ = inst_low7_;
      context->operand_1__ = context->operand_1_;
      break;
  }
}
```

In short, flag verification is as follows.
1. In early part of instructions
   * reads two bytes from input
   * add some two-byte value with read value in step 1
   * check if sum is 0. if value is 0, process dies.
   * this means input should be two's complement of two-byte value
   * from this part I could figure out that flag starts with "CODEGATE2020"
2. Latter part
   * 0xdead is used as initial key
   * calculate key = (key * 2) ^ key;
   * xor two bytes from input and key
   * add result in step 3 and some two-byte value
   * result in step 4 should be 0.
   * goto step 2 and repeat

With either manual debugging or automation using script, challenge is solved.
```
CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}
```
