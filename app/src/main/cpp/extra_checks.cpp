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

// ═══════════════════════════════════════════════
// 1) rwxp memory segments — Frida gum/v8 indicators
// ═══════════════════════════════════════════════
static int check_rwxp() {
    char* buf = (char*)malloc(512 * 1024);
    if (!buf) return 0;
    if (rf("/proc/self/maps", buf, 512 * 1024) <= 0) { free(buf); return 0; }

    int rwxp_count = 0;
    int jit_count = 0;
    char* line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (!nl) break;
        // find perms field (after first space)
        char* sp = strchr(line, ' ');
        if (sp) {
            // check for "rwxp" in perms
            if (sp[1] == 'r' && sp[2] == 'w' && sp[3] == 'x' && sp[4] == 'p') {
                rwxp_count++;
                if (strstr(line, "[jit") || strstr(line, "[anon:jit")) jit_count++;
            }
        }
        line = nl + 1;
    }
    free(buf);
    // More than 2 non-JIT rwxp pages = suspicious
    return (rwxp_count - jit_count) > 2 ? 1 : 0;
}

// ═══════════════════════════════════════════════
// 2) App cloning detection
// ═══════════════════════════════════════════════
static int check_clone(const char* myPkg) {
    char* buf = (char*)malloc(512 * 1024);
    if (!buf) return 0;
    if (rf("/proc/self/maps", buf, 512 * 1024) <= 0) { free(buf); return 0; }

    // Search for foreign package paths in APK/dex mappings
    int foreign_apks = 0;
    char* line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (!nl) break;
        // Look for APK paths from other packages
        if (strstr(line, "/data/app/") && strstr(line, ".apk")) {
            if (myPkg && !strstr(line, myPkg)) {
                foreign_apks++;
            }
        }
        line = nl + 1;
    }
    free(buf);
    return foreign_apks > 0 ? 1 : 0;
}

// ═══════════════════════════════════════════════
// 3) Emulator hard signals (battery, GL)
// ═══════════════════════════════════════════════
static int check_emulator_hard() {
    char b[8192];

    // Battery: emulator often shows 0 temp/voltage
    // /sys/class/power_supply/battery/temp
    if (rf("/sys/class/power_supply/battery/temp", b, sizeof(b)) > 0) {
        int temp = atoi(b);
        if (temp == 0) return 1;
    }
    if (rf("/sys/class/power_supply/battery/voltage_now", b, sizeof(b)) > 0) {
        int v = atoi(b);
        if (v == 0) return 1;
    }

    // GL renderer emulator strings
    char* gl = (char*)malloc(64 * 1024);
    if (gl) {
        if (rf("/proc/cpuinfo", gl, 64 * 1024) > 0) {
            if (strstr(gl, "swiftshader") || strstr(gl, "android emulator") ||
                strstr(gl, "bluestacks") || strstr(gl, "genymotion")) {
                free(gl);
                return 1;
            }
        }
        free(gl);
    }

    return 0;
}

// ═══════════════════════════════════════════════
// 4) Debug flag check (Build.FLAG_DEBUGGABLE)
//    — actual check happens in Kotlin, but we expose the surface
// ═══════════════════════════════════════════════
static int check_debug_flag() {
    // Look for adb wireless / port 5555 listening
    char b[65536];
    if (rf("/proc/net/tcp", b, sizeof(b)) > 0) {
        if (strstr(b, ":15B3 ")) return 1;  // 5555 in hex = 0x15B3
    }
    return 0;
}

// ═══════════════════════════════════════════════
// Bitmask: 1=rwxp | 2=clone | 4=emulator_hard | 8=debug_port
// ═══════════════════════════════════════════════
extern "C" JNIEXPORT jint JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeExtraFlags(JNIEnv* env, jobject, jstring pkgName) {
    int f = 0;
    if (check_rwxp())           f |= 1;
    const char* p = nullptr;
    if (pkgName) p = env->GetStringUTFChars(pkgName, nullptr);
    if (check_clone(p))         f |= 2;
    if (p) env->ReleaseStringUTFChars(pkgName, p);
    if (check_emulator_hard())  f |= 4;
    if (check_debug_flag())     f |= 8;
    return f;
}
