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

static int contains_any(const char* hay, const char* const* needles, int n) {
    for (int i = 0; i < n; i++) if (strstr(hay, needles[i])) return 1;
    return 0;
}

// ═══════════════════════════════════════════════
// 1) QEMU driver artifacts (ysrc, reveny)
// ═══════════════════════════════════════════════
static int check_qemu_artifacts() {
    const char* paths[] = {
        "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/qemu_trace",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props",
        "/dev/goldfish_pipe", "/dev/goldfish_sync",
        "/dev/socket/genyd", "/dev/socket/baseband_genyd",
    };
    for (auto p : paths) {
        long fd = sc_openat(AT_FDCWD_, p, O_RDONLY_, 0);
        if (fd >= 0) { sc_close((int)fd); return 1; }
    }
    return 0;
}

// ═══════════════════════════════════════════════
// 2) ARM translation on x86 (reveny - very reliable)
//    If CPU is x86 but supports ARM → translation layer = emulator
// ═══════════════════════════════════════════════
static int check_arm_translation() {
    char b[4096];
    if (rf("/system/build.prop", b, sizeof(b)) <= 0) {
        // fallback to /proc/cpuinfo
        if (rf("/proc/cpuinfo", b, sizeof(b)) <= 0) return 0;
    }

    int is_x86_cpu = (strstr(b, "x86") != nullptr || strstr(b, "i686") != nullptr);
    if (!is_x86_cpu) return 0;

    // x86 CPU supporting ARM = translation = emulator (BlueStacks, Nox, LDPlayer)
    char abi[1024];
    if (rf("/proc/cpuinfo", abi, sizeof(abi)) > 0) {
        int has_arm = (strstr(abi, "armv7") != nullptr || strstr(abi, "aarch64") != nullptr);
        if (has_arm) return 1;
    }
    return 0;
}

// ═══════════════════════════════════════════════
// 3) Native Bridge property (reveny, DroidProbe)
//    ro.dalvik.vm.native.bridge = libhoudini.so (Intel ARM translator)
// ═══════════════════════════════════════════════
static int check_native_bridge() {
    char b[1024];
    if (rf("/system/build.prop", b, sizeof(b)) > 0) {
        if (strstr(b, "ro.dalvik.vm.native.bridge=libhoudini") ||
            strstr(b, "ro.dalvik.vm.native.bridge=libndk") ||
            strstr(b, "ro.enable.native.bridge.exec") ||
            strstr(b, "ro.dalvik.vm.isa.arm") ||
            strstr(b, "ro.dalvik.vm.isa.arm64")) {
            return 1;
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════
// 4) Emulator-specific build props (rating-based, anti-counterfeit)
//    Score > 3 = emulator
// ═══════════════════════════════════════════════
static int check_build_props_rating() {
    char b[16384];
    if (rf("/system/build.prop", b, sizeof(b)) <= 0) return 0;

    int score = 0;

    // Product
    const char* product_tokens[] = {
        "sdk", "sdk_x86", "sdk_google", "google_sdk", "Andy",
        "Droid4X", "nox", "vbox86p", "ttVM_Hdragon", "emulator"
    };
    if (contains_any(b, product_tokens, 10)) score++;

    // Hardware
    const char* hw_tokens[] = {
        "goldfish", "vbox86", "nox", "ttVM_x86", "ranchu", "cutf_cvm"
    };
    if (contains_any(b, hw_tokens, 6)) score += 2;

    // Fingerprint (very reliable)
    if (strstr(b, "generic/sdk/generic") ||
        strstr(b, "generic_x86/sdk_x86") ||
        strstr(b, "vbox86p") ||
        strstr(b, "generic_x86_64") ||
        strstr(b, "generic/google_sdk/generic")) {
        score += 3;
    }

    // Manufacturer
    const char* manu_tokens[] = {
        "Genymotion", "unknown", "Andy", "nox", "TiantianVM"
    };
    if (contains_any(b, manu_tokens, 5)) score++;

    // Brand
    if (strstr(b, "generic") || strstr(b, "generic_x86") ||
        strstr(b, "TTVM") || strstr(b, "Andy")) {
        score++;
    }

    // Model
    const char* model_tokens[] = {
        "Emulator", "google_sdk", "Droid4X", "TiantianVM", "Andy",
        "Android SDK built for x86", "Android SDK built for x86_64",
        "sdk_gphone"
    };
    if (contains_any(b, model_tokens, 8)) score += 2;

    return score > 3 ? 1 : 0;
}

// ═══════════════════════════════════════════════
// 5) Shared folder emulator (BlueStacks - anti-counterfeit)
// ═══════════════════════════════════════════════
static int check_shared_folder() {
    const char* folders[] = {
        "/sdcard/windows/BstSharedFolder",
        "/sdcard/BstSharedFolder",
        "/mnt/windows/BstSharedFolder",
    };
    for (auto p : folders) {
        long fd = sc_openat(AT_FDCWD_, p, O_RDONLY_, 0);
        if (fd >= 0) { sc_close((int)fd); return 1; }
    }
    return 0;
}

// ═══════════════════════════════════════════════
// 6) QEMU kernel strings (DroidProbe, reveny)
// ═══════════════════════════════════════════════
static int check_qemu_kernel() {
    char b[4096];
    // Kernel version often contains "qemu"
    if (rf("/proc/version", b, sizeof(b)) > 0) {
        if (strstr(b, "qemu") || strstr(b, "ranchu") || strstr(b, "goldfish")) return 1;
    }
    // init service
    if (rf("/proc/cmdline", b, sizeof(b)) > 0) {
        if (strstr(b, "qemu=") || strstr(b, "androidboot.hardware=ranchu") ||
            strstr(b, "androidboot.hardware=goldfish")) return 1;
    }
    return 0;
}

// ═══════════════════════════════════════════════
// 7) /proc/self/task multi-instance detection (DroidProbe)
//    Cloning frameworks leave extra thread groups
// ═══════════════════════════════════════════════
static int check_task_leak() {
    // Normal app has reasonable thread count; > 80 suspicious
    // But this is soft signal — disabled by default
    char b[8192];
    if (rf("/proc/self/status", b, sizeof(b)) > 0) {
        const char* p = strstr(b, "Threads:");
        if (p) {
            int threads = atoi(p + 8);
            if (threads > 80) return 1;
        }
    }
    return 0;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeDeepEmulatorFlags(JNIEnv*, jobject) {
    int f = 0;
    if (check_qemu_artifacts())     f |= 1;
    if (check_arm_translation())    f |= 2;
    if (check_native_bridge())      f |= 4;
    if (check_build_props_rating()) f |= 8;
    if (check_shared_folder())      f |= 16;
    if (check_qemu_kernel())        f |= 32;
    if (check_task_leak())          f |= 64;
    return f;
}
