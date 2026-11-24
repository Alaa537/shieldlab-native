#include <jni.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "syscall.h"

static int rf(const char* path, char* buf, size_t max) {
    long fd = sc_openat(AT_FDCWD_, path, O_RDONLY_, 0);
    if (fd < 0) return -1;
    long n = sc_read((int)fd, buf, max - 1);
    sc_close((int)fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return (int)n;
}

static int check_tracer_pid() {
    char b[4096];
    if (rf("/proc/self/status", b, sizeof(b)) > 0) {
        const char* p = strstr(b, "TracerPid:");
        if (p && atoi(p + 10) != 0) return 1;
    }
    return 0;
}

static int check_frida() {
    char b[65536];
    if (rf("/proc/net/tcp", b, sizeof(b)) > 0 &&
        (strstr(b, ":69A2 ") || strstr(b, ":69A3 "))) return 1;
    if (rf("/proc/net/tcp6", b, sizeof(b)) > 0 &&
        (strstr(b, ":69A2 ") || strstr(b, ":69A3 "))) return 1;
    char m[32768];
    if (rf("/proc/self/maps", m, sizeof(m)) > 0 &&
        (strstr(m, "frida") || strstr(m, "gum-js"))) return 1;
    return 0;
}

static int check_root() {
    const char* ps[] = {
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/data/adb/magisk", "/data/adb/modules", "/dev/magisk"
    };
    for (auto p : ps) {
        long fd = sc_openat(AT_FDCWD_, p, O_RDONLY_, 0);
        if (fd >= 0) { sc_close((int)fd); return 1; }
    }
    return 0;
}

static int check_emulator() {
    char b[4096];
    if (rf("/proc/cpuinfo", b, sizeof(b)) > 0 &&
        (strstr(b, "goldfish") || strstr(b, "ranchu"))) return 1;
    if (rf("/system/build.prop", b, sizeof(b)) > 0 &&
        (strstr(b, "ro.kernel.qemu=1") || strstr(b, "ro.boot.qemu=1"))) return 1;
    return 0;
}

// Bit 0: tracer | 1: frida | 2: root | 3: emulator

static int check_selinux_status();
static int check_suspicious_libraries();

extern "C" JNIEXPORT jint JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeEnvFlags(JNIEnv*, jobject) {
    int f = 0;
    if (check_tracer_pid()) f |= 1;
    if (check_frida())      f |= 2;
    if (check_root())       f |= 4;
    if (check_emulator())   f |= 8;
    if (check_selinux_status()) f |= 16;      // KKND
    if (check_suspicious_libraries()) f |= 32; // SecurityRisk
    return f;
}

// فحص SELinux (من KKND)
static int check_selinux_status() {
    char b[256];
    if (rf("/sys/fs/selinux/enforce", b, sizeof(b)) > 0) {
        // إذا كانت القيمة 0 فهذا يعني أن SELinux في وضع Permissive (خطر)
        if (b[0] == '0') return 1;
    }
    return 0;
}

// فحص GOT/PLT Hook (من SecurityRisk)
// هذا فحص مبسط: يبحث عن مكتبات مشبوهة محملة في الذاكرة
static int check_suspicious_libraries() {
    char b[65536];
    if (rf("/proc/self/maps", b, sizeof(b)) > 0) {
        const char* suspicious[] = {
            "libfrida", "libxposed", "libsubstrate", "libhook",
            "libriru", "libzygisk", "libmagisk"
        };
        for (auto s : suspicious) {
            if (strstr(b, s)) return 1;
        }
    }
    return 0;
}
