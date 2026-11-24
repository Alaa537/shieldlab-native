#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "syscall.h"
#include "sha256.h"
#include "expected_hash.h"

#define TAG "ShieldLab"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}
static void hex32(const uint8_t* h, char out[65]) {
    for (int i = 0; i < 32; i++) snprintf(out + i*2, 3, "%02x", h[i]);
    out[64] = 0;
}

// Return: 0=match 1=mismatch 2=parse_error 3=open_error
// Also fills out_actual, out_expected, out_diag
static int do_extract(const char* path, char out_actual[65], char out_expected[65], char* diag, size_t diaglen) {
    snprintf(out_actual, 65, "NONE");
    const char* exp = EXPECTED_CERT_SHA256;
    strncpy(out_expected, exp, 64);
    out_expected[64] = 0;

    long fd = sc_openat(AT_FDCWD_, path, O_RDONLY_, 0);
    if (fd < 0) {
        snprintf(diag, diaglen, "open failed fd=%ld", fd);
        return 3;
    }
    long fsize = sc_lseek(fd, 0, SEEK_END_);
    if (fsize < 32) {
        snprintf(diag, diaglen, "file too small fsize=%ld", fsize);
        sc_close((int)fd);
        return 2;
    }

    // Find EOCD
    size_t tsz = fsize < 65557 ? (size_t)fsize : 65557;
    uint8_t* tail = (uint8_t*)malloc(tsz);
    if (!tail) { sc_close((int)fd); return 2; }
    sc_lseek(fd, fsize - (long)tsz, SEEK_SET_);
    if (sc_read(fd, tail, tsz) != (long)tsz) { free(tail); sc_close((int)fd); return 2; }

    int eocd = -1;
    for (int i = (int)tsz - 22; i >= 0; i--) {
        if (tail[i]==0x50 && tail[i+1]==0x4b && tail[i+2]==0x05 && tail[i+3]==0x06) {
            eocd = i; break;
        }
    }
    if (eocd < 0) { free(tail); sc_close((int)fd); snprintf(diag, diaglen, "EOCD not found"); return 2; }

    uint32_t cd_off = le32(tail + eocd + 16);
    free(tail);

    if (cd_off < 32 || cd_off >= (uint32_t)fsize) {
        sc_close((int)fd);
        snprintf(diag, diaglen, "cd_off invalid=%u fsize=%ld", cd_off, fsize);
        return 2;
    }

    // Read 24 bytes before CD: [8B V][16B magic]
    uint8_t footer[24];
    sc_lseek(fd, (long)cd_off - 24, SEEK_SET_);
    if (sc_read(fd, footer, 24) != 24) { sc_close((int)fd); return 2; }

    if (memcmp(footer + 8, "APK Sig Block 42", 16) != 0) {
        sc_close((int)fd);
        snprintf(diag, diaglen, "no APK Sig Block (v2/v3 sig missing)");
        return 2;
    }

    uint64_t V = le64(footer);
    if (V < 24 || V > 100ULL*1024*1024) {
        sc_close((int)fd);
        snprintf(diag, diaglen, "V out of range=%llu", (unsigned long long)V);
        return 2;
    }
    if ((uint64_t)cd_off < V + 8) {
        sc_close((int)fd);
        snprintf(diag, diaglen, "V too big for file V=%llu cd=%u", (unsigned long long)V, cd_off);
        return 2;
    }

    long bstart = (long)cd_off - 8 - (long)V;
    size_t total = (size_t)(V + 8);
    uint8_t* blk = (uint8_t*)malloc(total);
    if (!blk) { sc_close((int)fd); return 2; }
    sc_lseek(fd, bstart, SEEK_SET_);
    if (sc_read(fd, blk, total) != (long)total) {
        free(blk); sc_close((int)fd); return 2;
    }
    sc_close((int)fd);

    // Verify internal size
    if (le64(blk) != V) {
        free(blk);
        snprintf(diag, diaglen, "inner size mismatch");
        return 2;
    }

    uint64_t pos = 8;
    uint64_t end_pairs = V - 16;

    while (pos + 12 <= end_pairs) {
        uint64_t psz = le64(blk + pos);
        if (psz < 4 || pos + 8 + psz > end_pairs) break;

        uint32_t pid = le32(blk + pos + 8);

        if (pid == 0x7109871a || pid == 0xf05368c0) {
            uint8_t* v = blk + pos + 12;
            uint32_t vl = (uint32_t)(psz - 4);
            if (vl < 4) { pos += 8 + psz; continue; }

            uint32_t signers_len = le32(v);
            if (4 + (uint64_t)signers_len > vl || signers_len < 4) { pos += 8 + psz; continue; }

            uint8_t* signer = v + 4;
            uint32_t signer_len = le32(signer);
            if (4 + (uint64_t)signer_len > signers_len || signer_len < 4) { pos += 8 + psz; continue; }

            uint8_t* sd = signer + 4;
            uint32_t sd_len = le32(sd);
            if (4 + (uint64_t)sd_len > signer_len || sd_len < 4) { pos += 8 + psz; continue; }

            uint8_t* sdb = sd + 4;
            uint32_t dig_len = le32(sdb);
            if (4 + (uint64_t)dig_len > sd_len) { pos += 8 + psz; continue; }

            uint8_t* certs = sdb + 4 + dig_len;
            uint32_t certs_rem = sd_len - 4 - dig_len;
            if (certs_rem < 4) { pos += 8 + psz; continue; }

            uint32_t certs_len = le32(certs);
            if (4 + (uint64_t)certs_len > certs_rem || certs_len < 4) { pos += 8 + psz; continue; }

            uint8_t* cert = certs + 4;
            uint32_t cert_len = le32(cert);
            if (4 + (uint64_t)cert_len > certs_len) { pos += 8 + psz; continue; }

            uint8_t hash[32];
            sha256_ctx ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, cert + 4, cert_len);
            sha256_final(&ctx, hash);
            hex32(hash, out_actual);

            free(blk);
            snprintf(diag, diaglen, "cert_extracted len=%u", cert_len);

            // Compare
            if (strlen(exp) != 64 || strcmp(exp, "INJECT_HERE") == 0) {
                snprintf(diag, diaglen, "expected hash NOT injected (placeholder)");
                return 2;
            }
            for (int i = 0; i < 64; i++) {
                char a = out_actual[i], b = out_expected[i];
                if (a >= 'A' && a <= 'F') a = (char)(a + 32);
                if (b >= 'A' && b <= 'F') b = (char)(b + 32);
                if (a != b) return 1;
            }
            return 0;
        }
        pos += 8 + psz;
    }
    free(blk);
    snprintf(diag, diaglen, "no v2/v3 block found in pairs");
    return 2;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeCertHash(JNIEnv* env, jobject, jstring apkPath) {
    if (!apkPath) return env->NewStringUTF("NONE");
    const char* p = env->GetStringUTFChars(apkPath, nullptr);
    if (!p) return env->NewStringUTF("NONE");
    char actual[65], expected[65], diag[256];
    do_extract(p, actual, expected, diag, sizeof(diag));
    env->ReleaseStringUTFChars(apkPath, p);
    return env->NewStringUTF(actual);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeEnforceCert(JNIEnv* env, jobject, jstring apkPath) {
    if (!apkPath) return 2;
    const char* p = env->GetStringUTFChars(apkPath, nullptr);
    if (!p) return 2;
    char actual[65], expected[65], diag[256];
    int r = do_extract(p, actual, expected, diag, sizeof(diag));
    LOGE("enforce result=%d diag=%s actual=%s expected=%s", r, diag, actual, expected);
    env->ReleaseStringUTFChars(apkPath, p);
    return r;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeExpectedHash(JNIEnv* env, jobject) {
    return env->NewStringUTF(EXPECTED_CERT_SHA256);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeDiagnostic(JNIEnv* env, jobject, jstring apkPath) {
    if (!apkPath) return env->NewStringUTF("no path");
    const char* p = env->GetStringUTFChars(apkPath, nullptr);
    if (!p) return env->NewStringUTF("no path");
    char actual[65], expected[65], diag[256];
    int r = do_extract(p, actual, expected, diag, sizeof(diag));
    env->ReleaseStringUTFChars(apkPath, p);
    char out[512];
    snprintf(out, sizeof(out), "result=%d | %s", r, diag);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_shieldlab_Enforcement_nativeApkHash(JNIEnv* env, jobject, jstring apkPath) {
    if (!apkPath) return env->NewStringUTF("NONE");
    const char* p = env->GetStringUTFChars(apkPath, nullptr);
    if (!p) return env->NewStringUTF("NONE");
    long fd = sc_openat(AT_FDCWD_, p, O_RDONLY_, 0);
    env->ReleaseStringUTFChars(apkPath, p);
    if (fd < 0) return env->NewStringUTF("NONE");

    sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[65536];
    long n;
    while ((n = sc_read((int)fd, buf, sizeof(buf))) > 0)
        sha256_update(&ctx, buf, (size_t)n);
    sc_close((int)fd);
    if (n < 0) return env->NewStringUTF("NONE");

    uint8_t out[32];
    sha256_final(&ctx, out);
    char hex[65];
    hex32(out, hex);
    return env->NewStringUTF(hex);
}
