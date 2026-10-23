/*
 * scanner_hooks rule table (data).
 *
 * Textually included by scanner_hooks.cc from inside its anonymous namespace. Kept in a separate
 * file so scanner_hooks.cc stays focused on the interception engine while this file holds the bulky,
 * verbose rule rows and their argument-value arrays. Not a standalone translation unit: it depends on
 * the RuleCategory / ActionKind / CallbackId enums, the Rule struct, and kNoArg defined in
 * scanner_hooks.cc above the include, and it relies on that file's anonymous namespace for internal
 * linkage. Do not add include guards or #include it anywhere else.
 */

// --- argument value arrays (SystemProperties keys etc.) ---------------------
const char* const kPropDebuggableBool[] = {"ro.debuggable", "ro.boot.qemu",
                                           "debug.choreographer.vsync"};
const char* const kPropDebuggableQemu[] = {"ro.debuggable", "ro.boot.qemu"};
const char* const kPropDebuggableKernelQemu[] = {"ro.debuggable", "ro.kernel.qemu"};
const char* const kPropSecureBoot[] = {"ro.adb.secure", "ro.secure", "ro.boot.flash.locked"};
const char* const kPropBrand[] = {"ro.product.brand", "ro.product.manufacturer"};
const char* const kPropHardware[] = {"ro.hardware", "ro.product.name"};
const char* const kPropDevice[] = {"ro.product.device", "ro.product.model"};
const char* const kPropSkipWarn[] = {"debug.choreographer.skipwarning"};
const char* const kPropBuildType[] = {"ro.build.type"};
const char* const kPropBootState[] = {"ro.boot.verifiedbootstate"};
const char* const kPropBuildFingerprint[] = {"ro.build.fingerprint"};
const char* const kPropBuildTags[] = {"ro.build.tags"};
// Spoofed values for the property probes above, shared by the SystemProperties.get rule rows and
// the ProcessBuilder getprop-spoof in scanner_hooks_scripts.inc (single source for both paths).
const char* const kFakeSecureValue = "1";
const char* const kFakeDebuggableValue = "0";
const char* const kFakeBuildType = "user";
const char* const kFakeBuildTags = "release-keys";
const char* const kFakeVerifiedBootState = "green";
const char* const kFakeBrand = "google";
const char* const kFakeModel = "pixel";
const char* const kFakeHardware = "exynos2100";
const char* const kPropEmulator[] = {
    "init.svc.qemu-adb-keys", "init.svc.qemu-adb-setup", "init.svc.qemu-device-state",
    "init.svc.qemu-props", "init.svc_debug_pid.qemu-adb-keys",
    "init.svc_debug_pid.qemu-adb-setup", "init.svc_debug_pid.qemu-device-state",
    "init.svc_debug_pid.qemu-props", "qemu.hw.mainkeys", "qemu.sf.lcd_density",
    "ro.boot.qemu.avd_name", "ro.boot.qemu.camera_hq_edge_processing",
    "ro.boot.qemu.camera_protocol_ver", "ro.boot.qemu.cpuvulkan.version",
    "ro.boot.qemu.gltransport.drawFlushInterval", "ro.boot.qemu.gltransport.name",
    "ro.boot.qemu.hwcodec.avcdec", "ro.boot.qemu.hwcodec.hevcdec",
    "ro.boot.qemu.hwcodec.vpxdec", "ro.boot.qemu.settings.system.screen_off_timeout",
    "ro.boot.qemu.skin", "ro.boot.qemu.virtiowifi", "ro.boot.qemu.vsync", "ro.boot.qemu",
    "ro.boottime.qemu-adb-keys", "ro.boottime.qemu-adb-setup", "ro.boottime.qemu-device-state",
    "ro.boottime.qemu-props", "vendor.qemu.dev.bootcomplete", "vendor.qemu.sf.fake_camera",
    "vendor.qemu.timezone", "vendor.qemu.vport.bluetooth", "vendor.qemu.vport.modem"};
const char* const kSettingsSecure[] = {"install_non_market_apps",
                                       "unknown_sources_default_reversed"};
const char* const kSettingsPlayStore[] = {"phone_play_store_availability",
                                          "verifier_verify_adb_installs"};
const char* const kSettingsAdb[] = {"adb_enabled", "adb_wifi_enabled", "upload_apk_enable"};
// Play Integrity / SafetyNet service-bind actions that are redirected from the real Play/GMS
// package to the decoy helper app.
const char* const kIntegrityBindActions[] = {
    "com.google.android.play.core.integrityservice.BIND_INTEGRITY_SERVICE",
    "com.google.android.gms.safetynet.service.START"};
// android.content.Intent internals the bindService redirect reads (mAction) and rewrites
// (mPackage), and the package it repoints the bind at. "com.fake_market" is a decoy helper app
// that exposes stub integrity/SafetyNet services, so the bind resolves to it and returns benign
// results instead of hitting the real GMS/Play service.
constexpr const char* kIntentActionField = "mAction";
constexpr const char* kIntentPackageField = "mPackage";
constexpr const char* kBindServiceSpoofPackage = "com.fake_market";
// Root/emulator artifact paths; java.io.File.exists() on any of these is forced to false.
const char* const kRootPaths[] = {
    "/cache/magisk", "/data/adb/magisk", "/data/local/bin/su", "/data/local/su",
    "/data/local/xbin/su", "/sbin/.magisk", "/sbin/magisk", "/sbin/su", "/su/bin/su", "/su/bin",
    "/system/app/Superuser.apk", "/system/bin/.ext", "/system/bin/.su",
    "/system/bin/failsafe/su", "/system/bin/frida-server", "/system/bin/magisk",
    "/system/bin/su", "/system/framework/XposedBridge.jar", "/system/lib/libriruloader.so",
    "/system/lib/libxposed.so", "/system/lib64/libxposed.so", "/system/sd/xbin/su",
    "/system/usr/we-need-root/", "/system/xbin/.ext", "/system/xbin/daemonsu",
    "/system/xbin/magisk", "/system/xbin/su", "/vendor/bin/su",
    "/dev/goldfish_pipe", "/dev/qemu_pipe", "/proc/tty/drivers",
    "/system_ext/bin/init.qemu-adb-keys.sh", "/vendor/bin/qemu-adb-keys",
    "/vendor/bin/qemu-device-state", "/vendor/bin/qemu-props",
    "/vendor/lib64/libqemupipe.ranchu.so"};

#define ARR(a) (a), static_cast<int>(sizeof(a) / sizeof((a)[0]))

const char kFingerprint[] =
    "google/exynos2100/pixel:14/google/google:user/release-keys";

// java.util.Collections.EMPTY_LIST - the object kConstEmptyList rules force-return (resolved once
// at install by ResolveEmptyList).
constexpr const char* kCollectionsDescriptor = "Ljava/util/Collections;";
constexpr const char* kEmptyListFieldName = "EMPTY_LIST";
constexpr const char* kListDescriptor = "Ljava/util/List;";

// Google platform signing certificate (DER X.509). Used to build the fabricated Google PackageInfo
// returned for com.android.vending / com.google.android.gms queries.
const uint8_t kGoogleCertDer[] = {
    0x30, 0x82, 0x04, 0x43, 0x30, 0x82, 0x03, 0x2b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
    0xc2, 0xe0, 0x87, 0x46, 0x64, 0x4a, 0x30, 0x8d, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30, 0x74, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
    0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x13, 0x0d, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x56,
    0x69, 0x65, 0x77, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x47, 0x6f,
    0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x0b, 0x13, 0x07, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x31, 0x10, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x30, 0x1e, 0x17,
    0x0d, 0x30, 0x38, 0x30, 0x38, 0x32, 0x31, 0x32, 0x33, 0x31, 0x33, 0x33, 0x34, 0x5a, 0x17, 0x0d,
    0x33, 0x36, 0x30, 0x31, 0x30, 0x37, 0x32, 0x33, 0x31, 0x33, 0x33, 0x34, 0x5a, 0x30, 0x74, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69,
    0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d, 0x4d, 0x6f, 0x75, 0x6e,
    0x74, 0x61, 0x69, 0x6e, 0x20, 0x56, 0x69, 0x65, 0x77, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x0b, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x07, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69,
    0x64, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x41, 0x6e, 0x64, 0x72,
    0x6f, 0x69, 0x64, 0x30, 0x82, 0x01, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0d, 0x00, 0x30, 0x82, 0x01, 0x08, 0x02,
    0x82, 0x01, 0x01, 0x00, 0xab, 0x56, 0x2e, 0x00, 0xd8, 0x3b, 0xa2, 0x08, 0xae, 0x0a, 0x96, 0x6f,
    0x12, 0x4e, 0x29, 0xda, 0x11, 0xf2, 0xab, 0x56, 0xd0, 0x8f, 0x58, 0xe2, 0xcc, 0xa9, 0x13, 0x03,
    0xe9, 0xb7, 0x54, 0xd3, 0x72, 0xf6, 0x40, 0xa7, 0x1b, 0x1d, 0xcb, 0x13, 0x09, 0x67, 0x62, 0x4e,
    0x46, 0x56, 0xa7, 0x77, 0x6a, 0x92, 0x19, 0x3d, 0xb2, 0xe5, 0xbf, 0xb7, 0x24, 0xa9, 0x1e, 0x77,
    0x18, 0x8b, 0x0e, 0x6a, 0x47, 0xa4, 0x3b, 0x33, 0xd9, 0x60, 0x9b, 0x77, 0x18, 0x31, 0x45, 0xcc,
    0xdf, 0x7b, 0x2e, 0x58, 0x66, 0x74, 0xc9, 0xe1, 0x56, 0x5b, 0x1f, 0x4c, 0x6a, 0x59, 0x55, 0xbf,
    0xf2, 0x51, 0xa6, 0x3d, 0xab, 0xf9, 0xc5, 0x5c, 0x27, 0x22, 0x22, 0x52, 0xe8, 0x75, 0xe4, 0xf8,
    0x15, 0x4a, 0x64, 0x5f, 0x89, 0x71, 0x68, 0xc0, 0xb1, 0xbf, 0xc6, 0x12, 0xea, 0xbf, 0x78, 0x57,
    0x69, 0xbb, 0x34, 0xaa, 0x79, 0x84, 0xdc, 0x7e, 0x2e, 0xa2, 0x76, 0x4c, 0xae, 0x83, 0x07, 0xd8,
    0xc1, 0x71, 0x54, 0xd7, 0xee, 0x5f, 0x64, 0xa5, 0x1a, 0x44, 0xa6, 0x02, 0xc2, 0x49, 0x05, 0x41,
    0x57, 0xdc, 0x02, 0xcd, 0x5f, 0x5c, 0x0e, 0x55, 0xfb, 0xef, 0x85, 0x19, 0xfb, 0xe3, 0x27, 0xf0,
    0xb1, 0x51, 0x16, 0x92, 0xc5, 0xa0, 0x6f, 0x19, 0xd1, 0x83, 0x85, 0xf5, 0xc4, 0xdb, 0xc2, 0xd6,
    0xb9, 0x3f, 0x68, 0xcc, 0x29, 0x79, 0xc7, 0x0e, 0x18, 0xab, 0x93, 0x86, 0x6b, 0x3b, 0xd5, 0xdb,
    0x89, 0x99, 0x55, 0x2a, 0x0e, 0x3b, 0x4c, 0x99, 0xdf, 0x58, 0xfb, 0x91, 0x8b, 0xed, 0xc1, 0x82,
    0xba, 0x35, 0xe0, 0x03, 0xc1, 0xb4, 0xb1, 0x0d, 0xd2, 0x44, 0xa8, 0xee, 0x24, 0xff, 0xfd, 0x33,
    0x38, 0x72, 0xab, 0x52, 0x21, 0x98, 0x5e, 0xda, 0xb0, 0xfc, 0x0d, 0x0b, 0x14, 0x5b, 0x6a, 0xa1,
    0x92, 0x85, 0x8e, 0x79, 0x02, 0x01, 0x03, 0xa3, 0x81, 0xd9, 0x30, 0x81, 0xd6, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xc7, 0x7d, 0x8c, 0xc2, 0x21, 0x17, 0x56, 0x25,
    0x9a, 0x7f, 0xd3, 0x82, 0xdf, 0x6b, 0xe3, 0x98, 0xe4, 0xd7, 0x86, 0xa5, 0x30, 0x81, 0xa6, 0x06,
    0x03, 0x55, 0x1d, 0x23, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x80, 0x14, 0xc7, 0x7d, 0x8c, 0xc2,
    0x21, 0x17, 0x56, 0x25, 0x9a, 0x7f, 0xd3, 0x82, 0xdf, 0x6b, 0xe3, 0x98, 0xe4, 0xd7, 0x86, 0xa5,
    0xa1, 0x78, 0xa4, 0x76, 0x30, 0x74, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x43, 0x61,
    0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04,
    0x07, 0x13, 0x0d, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x56, 0x69, 0x65, 0x77,
    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x47, 0x6f, 0x6f, 0x67, 0x6c,
    0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13,
    0x07, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x13, 0x07, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x82, 0x09, 0x00, 0xc2, 0xe0, 0x87,
    0x46, 0x64, 0x4a, 0x30, 0x8d, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x6d, 0xd2, 0x52, 0xce, 0xef, 0x85, 0x30, 0x2c, 0x36,
    0x0a, 0xaa, 0xce, 0x93, 0x9b, 0xcf, 0xf2, 0xcc, 0xa9, 0x04, 0xbb, 0x5d, 0x7a, 0x16, 0x61, 0xf8,
    0xae, 0x46, 0xb2, 0x99, 0x42, 0x04, 0xd0, 0xff, 0x4a, 0x68, 0xc7, 0xed, 0x1a, 0x53, 0x1e, 0xc4,
    0x59, 0x5a, 0x62, 0x3c, 0xe6, 0x07, 0x63, 0xb1, 0x67, 0x29, 0x7a, 0x7a, 0xe3, 0x57, 0x12, 0xc4,
    0x07, 0xf2, 0x08, 0xf0, 0xcb, 0x10, 0x94, 0x29, 0x12, 0x4d, 0x7b, 0x10, 0x62, 0x19, 0xc0, 0x84,
    0xca, 0x3e, 0xb3, 0xf9, 0xad, 0x5f, 0xb8, 0x71, 0xef, 0x92, 0x26, 0x9a, 0x8b, 0xe2, 0x8b, 0xf1,
    0x6d, 0x44, 0xc8, 0xd9, 0xa0, 0x8e, 0x6c, 0xb2, 0xf0, 0x05, 0xbb, 0x3f, 0xe2, 0xcb, 0x96, 0x44,
    0x7e, 0x86, 0x8e, 0x73, 0x10, 0x76, 0xad, 0x45, 0xb3, 0x3f, 0x60, 0x09, 0xea, 0x19, 0xc1, 0x61,
    0xe6, 0x26, 0x41, 0xaa, 0x99, 0x27, 0x1d, 0xfd, 0x52, 0x28, 0xc5, 0xc5, 0x87, 0x87, 0x5d, 0xdb,
    0x7f, 0x45, 0x27, 0x58, 0xd6, 0x61, 0xf6, 0xcc, 0x0c, 0xcc, 0xb7, 0x35, 0x2e, 0x42, 0x4c, 0xc4,
    0x36, 0x5c, 0x52, 0x35, 0x32, 0xf7, 0x32, 0x51, 0x37, 0x59, 0x3c, 0x4a, 0xe3, 0x41, 0xf4, 0xdb,
    0x41, 0xed, 0xda, 0x0d, 0x0b, 0x10, 0x71, 0xa7, 0xc4, 0x40, 0xf0, 0xfe, 0x9e, 0xa0, 0x1c, 0xb6,
    0x27, 0xca, 0x67, 0x43, 0x69, 0xd0, 0x84, 0xbd, 0x2f, 0xd9, 0x11, 0xff, 0x06, 0xcd, 0xbf, 0x2c,
    0xfa, 0x10, 0xdc, 0x0f, 0x89, 0x3a, 0xe3, 0x57, 0x62, 0x91, 0x90, 0x48, 0xc7, 0xef, 0xc6, 0x4c,
    0x71, 0x44, 0x17, 0x83, 0x42, 0xf7, 0x05, 0x81, 0xc9, 0xde, 0x57, 0x3a, 0xf5, 0x5b, 0x39, 0x0d,
    0xd7, 0xfd, 0xb9, 0x41, 0x86, 0x31, 0x89, 0x5d, 0x5f, 0x75, 0x9f, 0x30, 0x11, 0x26, 0x87, 0xff,
    0x62, 0x14, 0x10, 0xc0, 0x69, 0x30, 0x8a,
};
const size_t kGoogleCertDerLen = sizeof(kGoogleCertDer);

// Google package names whose getPackageInfo query returns the fabricated Google PackageInfo.
const char* const kGooglePackages[] = {"com.android.vending", "com.google.android.gms"};

// The rule table. Member names match exactly; add one row per name or overload. A row with
// is_field set spoofs a static field; otherwise it intercepts a method.
#define RASP RuleCategory::kRaspBypass
#define SSLB RuleCategory::kSslBypass
#define PKG RuleCategory::kPackageManipulation
#define DBG RuleCategory::kDebuggerBypass
#define SEC RuleCategory::kSecureFlagBypass
const Rule kRules[] = {
    // android.os.Debug
    // Debugger-detection rules live in their own category. They return "not connected", except on
    // the stack of Debug.waitForDebugger()'s startup poll (see CalledFromWaitForDebugger in
    // scanner_hooks.cc), so a process started waiting for a debugger does not hang at startup.
    {DBG, "Landroid/os/Debug;", "isDebuggerConnected", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, false, 0, nullptr},
    {DBG, "Landroid/os/Debug;", "waitingForDebugger", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, false, 0, nullptr},

    // android.os.Build fields
    {RASP, "Landroid/os/Build;", "IS_ENG", true, kNoArg, nullptr, 0, ActionKind::kFieldSetBool,
     false, 0, nullptr},
    {RASP, "Landroid/os/Build;", "IS_USERDEBUG", true, kNoArg, nullptr, 0,
     ActionKind::kFieldSetBool, false, 0, nullptr},
    {RASP, "Landroid/os/Build;", "IS_DEBUGGABLE", true, kNoArg, nullptr, 0,
     ActionKind::kFieldSetBool, false, 0, nullptr},
    {RASP, "Landroid/os/Build;", "IS_EMULATOR", true, kNoArg, nullptr, 0,
     ActionKind::kFieldSetBool, false, 0, nullptr},
    {RASP, "Landroid/os/Build;", "IS_USER", true, kNoArg, nullptr, 0, ActionKind::kFieldSetBool,
     true, 0, nullptr},
    {RASP, "Landroid/os/Build;", "TAGS", true, kNoArg, nullptr, 0, ActionKind::kFieldSetString,
     false, 0, "release-keys"},
    {RASP, "Landroid/os/Build;", "BRAND", true, kNoArg, nullptr, 0, ActionKind::kFieldSetString,
     false, 0, "google"},
    {RASP, "Landroid/os/Build;", "MANUFACTURER", true, kNoArg, nullptr, 0,
     ActionKind::kFieldSetString, false, 0, "google"},
    {RASP, "Landroid/os/Build;", "PRODUCT", true, kNoArg, nullptr, 0, ActionKind::kFieldSetString,
     false, 0, "exynos2100"},
    {RASP, "Landroid/os/Build;", "HARDWARE", true, kNoArg, nullptr, 0, ActionKind::kFieldSetString,
     false, 0, "exynos2100"},
    {RASP, "Landroid/os/Build;", "FINGERPRINT", true, kNoArg, nullptr, 0,
     ActionKind::kFieldSetString, false, 0, kFingerprint},
    {RASP, "Landroid/os/Build;", "DEVICE", true, kNoArg, nullptr, 0, ActionKind::kFieldSetString,
     false, 0, "pixel"},
    {RASP, "Landroid/os/Build;", "MODEL", true, kNoArg, nullptr, 0, ActionKind::kFieldSetString,
     false, 0, "pixel"},

    // android.os.Build.getRadioVersion
    {RASP, "Landroid/os/Build;", "getRadioVersion", false, kNoArg, nullptr, 0,
     ActionKind::kConstString, false, 0, "exynos2100,exynos2100"},

    // android.os.SystemProperties, gated by the property name argument
    {RASP, "Landroid/os/SystemProperties;", "getBoolean", false, 0, ARR(kPropDebuggableBool),
     ActionKind::kConstBool, false, 0, nullptr},
    {RASP, "Landroid/os/SystemProperties;", "getInt", false, 0, ARR(kPropSkipWarn),
     ActionKind::kConstInt, false, 100000000, nullptr},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropBuildType),
     ActionKind::kConstString, false, 0, kFakeBuildType},
    {RASP, "Landroid/os/SystemProperties;", "getInt", false, 0, ARR(kPropDebuggableQemu),
     ActionKind::kConstInt, false, 0, nullptr},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropDebuggableKernelQemu),
     ActionKind::kConstString, false, 0, kFakeDebuggableValue},
    {RASP, "Landroid/os/SystemProperties;", "getBoolean", false, 0, ARR(kPropSecureBoot),
     ActionKind::kConstBool, true, 0, nullptr},
    {RASP, "Landroid/os/SystemProperties;", "getInt", false, 0, ARR(kPropSecureBoot),
     ActionKind::kConstInt, false, 1, nullptr},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropSecureBoot),
     ActionKind::kConstString, false, 0, kFakeSecureValue},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropBootState),
     ActionKind::kConstString, false, 0, kFakeVerifiedBootState},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropBrand),
     ActionKind::kConstString, false, 0, kFakeBrand},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropHardware),
     ActionKind::kConstString, false, 0, kFakeHardware},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropBuildFingerprint),
     ActionKind::kConstString, false, 0, kFingerprint},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropDevice),
     ActionKind::kConstString, false, 0, kFakeModel},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropBuildTags),
     ActionKind::kConstString, false, 0, kFakeBuildTags},
    {RASP, "Landroid/os/SystemProperties;", "get", false, 0, ARR(kPropEmulator),
     ActionKind::kConstNull, false, 0, nullptr},

    // android.provider.Settings.Secure / .Global getInt, gated by the setting name argument
    {RASP, "Landroid/provider/Settings$Secure;", "getInt", false, 1, ARR(kSettingsSecure),
     ActionKind::kConstInt, false, 0, nullptr},
    {RASP, "Landroid/provider/Settings$Global;", "getInt", false, 1, ARR(kSettingsPlayStore),
     ActionKind::kConstInt, false, 1, nullptr},
    {RASP, "Landroid/provider/Settings$Global;", "getInt", false, 1, ARR(kSettingsAdb),
     ActionKind::kConstInt, false, 0, nullptr},

    // android.security.keystore.*
    {RASP, "Landroid/security/keystore/KeyInfo;", "isInsideSecureHardware", false, kNoArg, nullptr,
     0, ActionKind::kConstBool, true, 0, nullptr},
    {RASP, "Landroid/security/keystore/KeyInfo;", "getSecurityLevel", false, kNoArg, nullptr, 0,
     ActionKind::kConstInt, false, 2, nullptr},
    {RASP, "Landroid/security/keystore/KeyGenParameterSpec;", "isStrongBoxBacked", false, kNoArg,
     nullptr, 0, ActionKind::kConstBool, false, 0, nullptr},
    {RASP, "Landroid/security/keystore/KeyProtection;", "isStrongBoxBacked", false, kNoArg, nullptr,
     0, ActionKind::kConstBool, true, 0, nullptr},

    // java.io.File.exists, forced to false when this.path is a root/emulator artifact.
    {RASP, "Ljava/io/File;", "exists", false, kNoArg, ARR(kRootPaths), ActionKind::kConstBool,
     false, 0, nullptr, "path"},

    // android.hardware.SensorManager sensor enumeration -> empty list (emulators expose
    // characteristic "Goldfish" sensors). getFullSensorList / getFullDynamicSensorList are
    // abstract on SensorManager and concrete only on SystemSensorManager, so they target the impl.
    {RASP, "Landroid/hardware/SensorManager;", "getSensorList", false, kNoArg, nullptr, 0,
     ActionKind::kConstEmptyList, false, 0, nullptr},
    {RASP, "Landroid/hardware/SystemSensorManager;", "getFullSensorList", false, kNoArg, nullptr, 0,
     ActionKind::kConstEmptyList, false, 0, nullptr},
    {RASP, "Landroid/hardware/SystemSensorManager;", "getFullDynamicSensorList", false, kNoArg,
     nullptr, 0, ActionKind::kConstEmptyList, false, 0, nullptr},

    // Package / signature identity checks (match PackageManager and its IPackageManager proxy, and
    // their subtypes/implementors). Fields after this_field: match_subtypes, return_shorty.
    {RASP, "Landroid/content/pm/PackageManager;", "hasSigningCertificate", false, kNoArg, nullptr,
     0, ActionKind::kConstBool, true, 0, nullptr, nullptr, true, 'Z'},
    {RASP, "Landroid/content/pm/IPackageManager;", "hasSigningCertificate", false, kNoArg, nullptr,
     0, ActionKind::kConstBool, true, 0, nullptr, nullptr, true, 'Z'},
    {RASP, "Landroid/content/pm/PackageManager;", "checkSignatures", false, kNoArg, nullptr, 0,
     ActionKind::kConstInt, false, 0, nullptr, nullptr, true, 'I'},
    {RASP, "Landroid/content/pm/IPackageManager;", "checkSignatures", false, kNoArg, nullptr, 0,
     ActionKind::kConstInt, false, 0, nullptr, nullptr, true, 'I'},
    {RASP, "Landroid/content/pm/Signature;", "equals", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, true, 0, nullptr, nullptr, false, 'Z'},
    {RASP, "Landroid/content/pm/SigningDetails;", "equals", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, true, 0, nullptr, nullptr, false, 'Z'},

    // SSL / TLS trust and hostname verification. These accept everything: void checks return
    // without throwing, boolean verifications return true. Interface/base rules use match_subtypes
    // so every app or library implementor is covered.
    {SSLB, "Lorg/conscrypt/NativeCrypto$SSLHandshakeCallbacks;", "verifyCertificateChain", false,
     kNoArg, nullptr, 0, ActionKind::kConstVoid, false, 0, nullptr, nullptr, true, 'V'},
    {SSLB, "Lorg/conscrypt/ConscryptEngine;", "verifyCertificateChain", false, kNoArg, nullptr, 0,
     ActionKind::kConstVoid, false, 0, nullptr, nullptr, false, 'V'},
    {SSLB, "Ljavax/net/ssl/X509TrustManager;", "checkClientTrusted", false, kNoArg, nullptr, 0,
     ActionKind::kConstVoid, false, 0, nullptr, nullptr, true, 'V'},
    {SSLB, "Ljavax/net/ssl/X509TrustManager;", "checkServerTrusted", false, kNoArg, nullptr, 0,
     ActionKind::kConstVoid, false, 0, nullptr, nullptr, true, 'V'},
    {SSLB, "Lorg/apache/http/conn/ssl/X509HostnameVerifier;", "verify", false, kNoArg, nullptr, 0,
     ActionKind::kConstVoid, false, 0, nullptr, nullptr, true, 'V'},
    {SSLB, "Lsun/security/provider/certpath/PKIXMasterCertPathValidator;", "validate", false, kNoArg,
     nullptr, 0, ActionKind::kConstVoid, false, 0, nullptr, nullptr, false, 'V'},
    {SSLB, "Lorg/conscrypt/ConscryptHostnameVerifier;", "verify", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, true, 0, nullptr, nullptr, true, 'Z'},
    {SSLB, "Lorg/conscrypt/OkHostnameVerifier;", "verify", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, true, 0, nullptr, nullptr, false, 'Z'},
    {SSLB, "Ljavax/net/ssl/HostnameVerifier;", "verify", false, kNoArg, nullptr, 0,
     ActionKind::kConstBool, true, 0, nullptr, nullptr, true, 'Z'},

    // Redirect Play Integrity / SafetyNet service binds to the decoy helper app
    // (kBindServiceSpoofPackage), which answers with stub/benign results. Mutates the Intent
    // argument's package, then lets bindService run. Matches ContextImpl and ContextWrapper exactly
    // (the two classes that declare bindService). int_value carries the callback id.
    {PKG, "Landroid/app/ContextImpl;", "bindService", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutate, false, kCbBindServiceSpoof, nullptr},
    {PKG, "Landroid/content/ContextWrapper;", "bindService", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutate, false, kCbBindServiceSpoof, nullptr},

    // secure_flag_bypass: strip FLAG_SECURE (0x2000) from the Window flags argument so a screen can
    // never be marked secure (blocking screenshots / screen capture). A mutate-and-proceed rule: it
    // clears the bit in the primitive int argument in place, then lets the method run. addFlags(int)
    // has the flags in arg 0; setFlags(int flags, int mask) has them in args 0 and 1 (clearing the
    // mask bit leaves the real flag untouched rather than setting it).
    {SEC, "Landroid/view/Window;", "addFlags", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutate, false, kCbClearSecureFlag, nullptr},
    {SEC, "Landroid/view/Window;", "setFlags", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutate, false, kCbClearSecureFlag, nullptr},

    // --- callback-based rules: managed invoke, object building, cross-frame state ----------------
    // Fields after string_value: this_field, match_subtypes, return_shorty.

    // SSL: X509TrustManager.checkServerTrusted(List overload) -> Arrays.asList(chain). return_shorty
    // 'L' selects the List-returning overload (the void overload is the kConstVoid rule above).
    {SSLB, "Ljavax/net/ssl/X509TrustManager;", "checkServerTrusted", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackReturn, false, kCbCheckServerTrustedList, nullptr, nullptr, true, 'L'},

    // SSL: WebViewClient.onReceivedSslError(view, handler, error) -> handler.proceed(), return void.
    {SSLB, "Landroid/webkit/WebViewClient;", "onReceivedSslError", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackReturn, false, kCbWebViewProceed, nullptr, nullptr, true, 0},

    // SSL: SSLPeerUnverifiedException.<init> -> force the void-returning caller to return (OkHttp
    // CertificatePinner bypass). The callback checks the caller is void-returning before acting.
    {SSLB, "Ljavax/net/ssl/SSLPeerUnverifiedException;", "<init>", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutate, false, kCbSslPeerUnverifiedStepOut, nullptr},

    // getPackageInfo("com.android.vending"/gms, ...) -> fabricated Google PackageInfo built off
    // the embedded Google signing cert (no app cert needed).
    {PKG, "Landroid/content/pm/PackageManager;", "getPackageInfo", false, 0, ARR(kGooglePackages),
     ActionKind::kCallbackReturn, false, kCbFakeGooglePackageInfo, nullptr, nullptr, true, 0},
    {PKG, "Landroid/content/pm/IPackageManager;", "getPackageInfo", false, 0, ARR(kGooglePackages),
     ActionKind::kCallbackReturn, false, kCbFakeGooglePackageInfo, nullptr, nullptr, true, 0},

    // RASP: ApplicationInfo.flags debuggable bit. The field read cannot be intercepted, so clear
    // FLAG_DEBUGGABLE on the ApplicationInfo objects returned by getApplicationInfo (mutate-return).
    {RASP, "Landroid/content/pm/PackageManager;", "getApplicationInfo", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutateReturn, false, kCbClearApplicationInfoDebuggable, nullptr, nullptr,
     true, 0},
    {RASP, "Landroid/content/pm/IPackageManager;", "getApplicationInfo", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutateReturn, false, kCbClearApplicationInfoDebuggable, nullptr, nullptr,
     true, 0},

    // RASP: java.lang.ProcessBuilder.start(). Shell-based probes exec commands (which su / getprop /
    // su); rewrite the receiver's command list so they yield benign faked output, then let start()
    // run (mutate-and-proceed).
    {RASP, "Ljava/lang/ProcessBuilder;", "start", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackMutate, false, kCbProcessBuilderSpoofCommand, nullptr},

    // RASP: java.util.jar.JarFile.maybeInstantiateVerifier(). Disable JAR/APK signature verification
    // on the receiver (verify=false, jv=null) and skip the method body (force-return void).
    {RASP, "Ljava/util/jar/JarFile;", "maybeInstantiateVerifier", false, kNoArg, nullptr, 0,
     ActionKind::kCallbackReturn, false, kCbJarFileSkipVerifier, nullptr, nullptr, false, 0},
};
#undef RASP
#undef SSLB
#undef PKG
#undef DBG
#undef SEC
#undef ARR
