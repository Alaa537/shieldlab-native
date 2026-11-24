#include <jni.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
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

// 1. كشف المحاكي عبر بيانات المستشعرات (Vigil Style)
static int check_sensor_noise() {
    // محاكي نادراً ما يحاكي ضوضاء المستشعرات بدقة
    // نبحث عن قيم مستشعرات غير طبيعية (0.0 أو قيم ثابتة تماماً)
    char b[4096];
    if (rf("/sys/class/sensors/accelerometer/device/name", b, sizeof(b)) > 0) {
        if (strstr(b, "Goldfish") || strstr(b, "Emulator")) return 1;
    }
    return 0;
}

// 2. كشف OverlayFS (دليل على Root/إخفاء)
static int check_overlayfs() {
    char b[8192];
    if (rf("/proc/mounts", b, sizeof(b)) > 0) {
        if (strstr(b, "overlay") && strstr(b, "/system")) return 1;
    }
    return 0;
}

// 3. كشف Native Methods المشبوهة (AndroidShield Style)
// إذا كانت الدوال الأمنية أصبحت Native فجأة بدون سبب، فهذا مؤشر على حقن
static int check_suspicious_native() {
    // هذه فحوصات Level-Kotlin عادةً، لكن نترك بصمة هنا
    return 0; // سنقوم بمعظم هذا الفحص في Kotlin
}

extern "C" JNIEXPORT jint JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeVigilFlags(JNIEnv*, jobject) {
    int f = 0;
    if (check_sensor_noise())      f |= 1;  // sensor_anomaly
    if (check_overlayfs())         f |= 2;  // overlayfs
    if (check_suspicious_native()) f |= 4;  // suspicious_native
    return f;
}
