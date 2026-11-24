#ifndef SHIELD_SYSCALL_H
#define SHIELD_SYSCALL_H
#include <stddef.h>

#if defined(__aarch64__)
#define NR_OPENAT 56
#define NR_CLOSE  57
#define NR_LSEEK  62
#define NR_READ   63
#define AT_FDCWD_ (-100)
#define O_RDONLY_ 0
#define SEEK_SET_ 0
#define SEEK_END_ 2

static inline long sc_openat(int d, const char* p, int f, int m) {
    register long x8 __asm__("x8") = NR_OPENAT;
    register long x0 __asm__("x0") = d;
    register long x1 __asm__("x1") = (long)p;
    register long x2 __asm__("x2") = f;
    register long x3 __asm__("x3") = m;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
static inline long sc_read(int fd, void* b, size_t c) {
    register long x8 __asm__("x8") = NR_READ;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static inline long sc_close(int fd) {
    register long x8 __asm__("x8") = NR_CLOSE;
    register long x0 __asm__("x0") = fd;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}
static inline long sc_lseek(int fd, long o, int w) {
    register long x8 __asm__("x8") = NR_LSEEK;
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = o;
    register long x2 __asm__("x2") = w;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
#else
#include <fcntl.h>
#include <unistd.h>
#define AT_FDCWD_ AT_FDCWD
#define O_RDONLY_ O_RDONLY
#define SEEK_SET_ SEEK_SET
#define SEEK_END_ SEEK_END
static inline long sc_openat(int d,const char*p,int f,int m){return openat(d,p,f,m);}
static inline long sc_read(int fd,void*b,size_t c){return read(fd,b,c);}
static inline long sc_close(int fd){return close(fd);}
static inline long sc_lseek(int fd,long o,int w){return lseek(fd,o,w);}
#endif
#endif
