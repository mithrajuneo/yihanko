package com.baby.ihanko;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "[Liapp Bypass]";

    // ============================================================
    // 루팅 관련 파일 경로
    // ============================================================
    private static final Set<String> ROOT_PATHS = new HashSet<>(Arrays.asList(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99telecominfra",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su-backup"
    ));

    private static final Set<String> MAGISK_PATHS = new HashSet<>(Arrays.asList(
            "/sbin/.magisk",
            "/sbin/magisk",
            "/system/bin/magisk",
            "/data/adb/magisk",
            "/data/adb/magisk.img",
            "/data/adb/modules",
            "/cache/magisk.log"
    ));

    private static final Set<String> FRIDA_PATHS = new HashSet<>(Arrays.asList(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent",
            "/sdcard/frida-server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server"
    ));

    private static final Set<String> BUSYBOX_PATHS = new HashSet<>(Arrays.asList(
            "/system/xbin/busybox",
            "/system/bin/busybox",
            "/sbin/busybox",
            "/data/local/bin/busybox"
    ));

    // 루팅 관련 패키지명 (자기 자신 포함)
    private static final Set<String> ROOT_PACKAGES = new HashSet<>(Arrays.asList(
            "com.example.liappbypass",
            "com.topjohnwu.magisk",
            "io.github.vvb2060.magisk",
            "com.topjohnwu.magisk.alpha",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.zhiqupk.root.global",
            "com.oasisfeng.greenify",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.saurik.substrate",
            "de.robv.android.xposed",
            "com.formyhm.hideroot",
            "com.amphoras.hidemyroot",
            "com.zachspong.temprootremovejb"
    ));

    // ★ Frida 라이브러리 탐지용 키워드 (loadLibrary 이름 체크 전용)
    // "gmain", "linjector"는 라이브러리 이름이 아니라 스레드 이름이므로 여기서 제외
    private static final String[] FRIDA_LIB_KEYWORDS = {
            "frida", "gadget"
    };

    // 스레드명 탐지용 키워드 (Thread.getName 전용)
    private static final String[] FRIDA_THREAD_KEYWORDS = {
            "frida", "gmain", "linjector", "gadget"
    };

    private static final Set<String> ALL_HIDDEN_PATHS = new HashSet<>();
    static {
        ALL_HIDDEN_PATHS.addAll(ROOT_PATHS);
        ALL_HIDDEN_PATHS.addAll(MAGISK_PATHS);
        ALL_HIDDEN_PATHS.addAll(FRIDA_PATHS);
        ALL_HIDDEN_PATHS.addAll(BUSYBOX_PATHS);
    }

    private static final String[] HIDDEN_PATH_KEYWORDS = {
            "magisk", "supersu", "superuser", "busybox",
            "frida", "xposed", "lsposed", "edxposed",
            "daemonsu", "zygisk", "liappbypass"
    };

    private static final Set<String> SU_FILENAMES = new HashSet<>(Arrays.asList(
            "su", "su-backup", "daemonsu"
    ));

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if ("com.example.liappbypass".equals(lpparam.packageName)) return;

        XposedBridge.log(TAG + " 후킹 시작: " + lpparam.packageName);

        hookFileChecks(lpparam);
        hookPackageManager(lpparam);
        hookRuntimeExec(lpparam);
        hookSystemProperties(lpparam);
        hookNativeLibraryCheck(lpparam);
        hookBuildProperties(lpparam);
        hookContentProviders(lpparam);
        hookNetworkChecks(lpparam);
        hookFridaDetection(lpparam);
        hookEnvironmentVariables(lpparam);

        XposedBridge.log(TAG + " 후킹 완료");
    }

    // ============================================================
    // 1. 파일 존재 여부 체크 우회
    // ============================================================
    private void hookFileChecks(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] methods = {"exists", "canRead", "canExecute", "isFile", "isDirectory"};

        for (String method : methods) {
            XposedHelpers.findAndHookMethod("java.io.File", lpparam.classLoader,
                    method, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String path = ((File) param.thisObject).getAbsolutePath();
                            if (shouldHidePath(path)) {
                                XposedBridge.log(TAG + " File." + method + "() 차단: " + path);
                                param.setResult(false);
                            }
                        }
                    });
        }

        XposedHelpers.findAndHookMethod("java.io.File", lpparam.classLoader,
                "length", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String path = ((File) param.thisObject).getAbsolutePath();
                        if (shouldHidePath(path)) {
                            param.setResult(0L);
                        }
                    }
                });

        XposedHelpers.findAndHookMethod("java.io.File", lpparam.classLoader,
                "listFiles", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        File[] files = (File[]) param.getResult();
                        if (files == null) return;
                        List<File> filtered = new ArrayList<>();
                        for (File f : files) {
                            if (!shouldHidePath(f.getAbsolutePath())) {
                                filtered.add(f);
                            }
                        }
                        param.setResult(filtered.toArray(new File[0]));
                    }
                });

        XposedHelpers.findAndHookMethod("java.io.File", lpparam.classLoader,
                "list", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String[] names = (String[]) param.getResult();
                        if (names == null) return;
                        String parentPath = ((File) param.thisObject).getAbsolutePath();
                        List<String> filtered = new ArrayList<>();
                        for (String name : names) {
                            if (!shouldHidePath(parentPath + "/" + name)) {
                                filtered.add(name);
                            }
                        }
                        param.setResult(filtered.toArray(new String[0]));
                    }
                });
    }

    // ============================================================
    // 2. PackageManager 우회
    //    ★ afterHookedMethod + null 반환 (JNI-safe)
    // ============================================================
    private void hookPackageManager(XC_LoadPackage.LoadPackageParam lpparam) {

        XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "getPackageInfo", String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String pkg = (String) param.args[0];
                        if (ROOT_PACKAGES.contains(pkg)) {
                            XposedBridge.log(TAG + " getPackageInfo 숨김: " + pkg);
                            param.setResult(null);
                        }
                    }
                });

        XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "getApplicationInfo", String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String pkg = (String) param.args[0];
                        if (ROOT_PACKAGES.contains(pkg)) {
                            XposedBridge.log(TAG + " getApplicationInfo 숨김: " + pkg);
                            param.setResult(null);
                        }
                    }
                });

        XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "getInstalledPackages", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        List<PackageInfo> packages = (List<PackageInfo>) param.getResult();
                        if (packages == null) return;
                        List<PackageInfo> filtered = new ArrayList<>();
                        for (PackageInfo pi : packages) {
                            if (!ROOT_PACKAGES.contains(pi.packageName)) {
                                filtered.add(pi);
                            }
                        }
                        param.setResult(filtered);
                    }
                });

        XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "getInstalledApplications", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        List<ApplicationInfo> apps = (List<ApplicationInfo>) param.getResult();
                        if (apps == null) return;
                        List<ApplicationInfo> filtered = new ArrayList<>();
                        for (ApplicationInfo ai : apps) {
                            if (!ROOT_PACKAGES.contains(ai.packageName)) {
                                filtered.add(ai);
                            }
                        }
                        param.setResult(filtered);
                    }
                });
    }

    // ============================================================
    // 3. Runtime.exec / ProcessBuilder 우회
    //    ★ su, magisk, busybox만 차단
    //    ★ getprop, id 등 일반 명령어는 전부 허용
    // ============================================================
    private void hookRuntimeExec(XC_LoadPackage.LoadPackageParam lpparam) {
        XC_MethodHook execStringHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String cmd = (String) param.args[0];
                if (isBlockedCommand(cmd)) {
                    XposedBridge.log(TAG + " Runtime.exec() 차단: " + cmd);
                    param.setThrowable(new java.io.IOException("Permission denied"));
                }
            }
        };

        XC_MethodHook execArrayHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String[] cmds = (String[]) param.args[0];
                if (cmds != null && cmds.length > 0) {
                    String fullCmd = String.join(" ", cmds);
                    if (isBlockedCommand(fullCmd)) {
                        XposedBridge.log(TAG + " Runtime.exec() 차단: " + fullCmd);
                        param.setThrowable(new java.io.IOException("Permission denied"));
                    }
                }
            }
        };

        XposedHelpers.findAndHookMethod("java.lang.Runtime", lpparam.classLoader,
                "exec", String.class, execStringHook);
        XposedHelpers.findAndHookMethod("java.lang.Runtime", lpparam.classLoader,
                "exec", String[].class, execArrayHook);
        XposedHelpers.findAndHookMethod("java.lang.Runtime", lpparam.classLoader,
                "exec", String.class, String[].class, File.class, execStringHook);
        XposedHelpers.findAndHookMethod("java.lang.Runtime", lpparam.classLoader,
                "exec", String[].class, String[].class, File.class, execArrayHook);

        XposedHelpers.findAndHookMethod("java.lang.ProcessBuilder", lpparam.classLoader,
                "start", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        try {
                            List<String> cmd = ((java.lang.ProcessBuilder) param.thisObject).command();
                            if (cmd != null) {
                                String fullCmd = String.join(" ", cmd);
                                if (isBlockedCommand(fullCmd)) {
                                    XposedBridge.log(TAG + " ProcessBuilder 차단: " + fullCmd);
                                    param.setThrowable(new java.io.IOException("Permission denied"));
                                }
                            }
                        } catch (Exception ignored) {}
                    }
                });
    }

    // ============================================================
    // 4. System Properties 우회
    // ============================================================
    private void hookSystemProperties(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod("android.os.SystemProperties", lpparam.classLoader,
                    "get", String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String key = (String) param.args[0];
                            String original = (String) param.getResult();
                            String filtered = filterProp(key, original);
                            if (!filtered.equals(original)) {
                                XposedBridge.log(TAG + " prop(" + key + "): " + original + " → " + filtered);
                            }
                            param.setResult(filtered);
                        }
                    });

            XposedHelpers.findAndHookMethod("android.os.SystemProperties", lpparam.classLoader,
                    "get", String.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            param.setResult(filterProp((String) param.args[0], (String) param.getResult()));
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + " SystemProperties hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 5. Native Library 로딩 차단
    //    ★★★ 핵심 수정:
    //    - "frida", "gadget"만 차단 (gmain/linjector는 라이브러리명 아님)
    //    - afterHookedMethod 사용 (void 메서드에 setResult 금지)
    //    - 정상 시스템 라이브러리는 절대 건드리지 않음
    // ============================================================
    private void hookNativeLibraryCheck(XC_LoadPackage.LoadPackageParam lpparam) {
        // ★ System.loadLibrary는 후킹하지 않음!
        // System.loadLibrary는 void 메서드라서 setResult(null)하면
        // 원본 호출이 스킵되어 정상 라이브러리도 로딩 안 됨
        // → 대신 File.exists 후킹으로 frida 라이브러리 경로만 숨기는 것으로 충분

        // System.load(절대경로)만 체크 - 경로에 frida가 포함된 경우만
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader,
                    "load", String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String path = (String) param.args[0];
                            if (path != null && isFridaLibrary(path)) {
                                XposedBridge.log(TAG + " System.load 차단: " + path);
                                // void 메서드이므로 아무것도 안 하고 스킵
                                // (원본 호출을 막으면서 예외도 던지지 않음)
                                param.setResult(null);
                            }
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + " NativeLib hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 6. Build Properties 위조
    // ============================================================
    private void hookBuildProperties(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.setStaticObjectField(Build.class, "TAGS", "release-keys");
            XposedBridge.log(TAG + " Build.TAGS = release-keys");

            String fp = Build.FINGERPRINT;
            if (fp != null && fp.contains("test-keys")) {
                XposedHelpers.setStaticObjectField(Build.class, "FINGERPRINT",
                        fp.replace("test-keys", "release-keys"));
            }

            if ("userdebug".equals(Build.TYPE)) {
                XposedHelpers.setStaticObjectField(Build.class, "TYPE", "user");
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Build hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 7. Settings (adb_enabled, dev mode)
    // ============================================================
    private void hookContentProviders(XC_LoadPackage.LoadPackageParam lpparam) {
        XC_MethodHook settingsHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                String key = (String) param.args[1];
                if ("adb_enabled".equals(key) || "development_settings_enabled".equals(key)) {
                    param.setResult(0);
                }
            }
        };

        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings$Global", lpparam.classLoader,
                    "getInt", android.content.ContentResolver.class, String.class, int.class,
                    settingsHook);
            XposedHelpers.findAndHookMethod("android.provider.Settings$Secure", lpparam.classLoader,
                    "getInt", android.content.ContentResolver.class, String.class, int.class,
                    settingsHook);
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Settings hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 8. Frida 포트(27042/27043) 차단
    // ============================================================
    private void hookNetworkChecks(XC_LoadPackage.LoadPackageParam lpparam) {
        XC_MethodHook socketHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                java.net.SocketAddress addr = (java.net.SocketAddress) param.args[0];
                if (addr instanceof java.net.InetSocketAddress) {
                    int port = ((java.net.InetSocketAddress) addr).getPort();
                    if (port == 27042 || port == 27043) {
                        param.setThrowable(new java.net.ConnectException("Connection refused"));
                    }
                }
            }
        };

        try {
            XposedHelpers.findAndHookMethod("java.net.Socket", lpparam.classLoader,
                    "connect", java.net.SocketAddress.class, int.class, socketHook);
            XposedHelpers.findAndHookMethod("java.net.Socket", lpparam.classLoader,
                    "connect", java.net.SocketAddress.class, socketHook);
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Network hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 9. Frida 스레드 탐지 우회
    // ============================================================
    private void hookFridaDetection(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod("java.lang.Thread", lpparam.classLoader,
                    "getName", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String name = (String) param.getResult();
                            if (name != null) {
                                String lower = name.toLowerCase();
                                for (String kw : FRIDA_THREAD_KEYWORDS) {
                                    if (lower.contains(kw)) {
                                        param.setResult("pool-" + Thread.currentThread().getId() + "-thread-1");
                                        return;
                                    }
                                }
                            }
                        }
                    });

            XposedHelpers.findAndHookMethod("java.lang.Thread", lpparam.classLoader,
                    "getAllStackTraces", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            @SuppressWarnings("unchecked")
                            Map<Thread, StackTraceElement[]> traces =
                                    (Map<Thread, StackTraceElement[]>) param.getResult();
                            if (traces == null) return;

                            Map<Thread, StackTraceElement[]> filtered = new java.util.HashMap<>();
                            for (Map.Entry<Thread, StackTraceElement[]> e : traces.entrySet()) {
                                String tn = e.getKey().getName();
                                if (tn != null) {
                                    String lower = tn.toLowerCase();
                                    boolean skip = false;
                                    for (String kw : FRIDA_THREAD_KEYWORDS) {
                                        if (lower.contains(kw)) {
                                            skip = true;
                                            break;
                                        }
                                    }
                                    if (skip) continue;
                                }
                                filtered.put(e.getKey(), e.getValue());
                            }
                            param.setResult(filtered);
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Frida hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 10. 환경변수 (PATH, LD_PRELOAD)
    // ============================================================
    private void hookEnvironmentVariables(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader,
                    "getenv", String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String key = (String) param.args[0];
                            String val = (String) param.getResult();
                            if (val == null) return;

                            if ("PATH".equals(key)) {
                                StringBuilder sb = new StringBuilder();
                                for (String seg : val.split(":")) {
                                    String l = seg.toLowerCase();
                                    if (!l.contains("magisk") && !l.contains("supersu") &&
                                            !l.contains("/su/") && !l.equals("/su")) {
                                        if (sb.length() > 0) sb.append(":");
                                        sb.append(seg);
                                    }
                                }
                                param.setResult(sb.toString());
                            } else if ("LD_PRELOAD".equals(key)) {
                                String l = val.toLowerCase();
                                if (l.contains("frida") || l.contains("gadget")) {
                                    param.setResult("");
                                }
                            }
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Env hook failed: " + t.getMessage());
        }
    }

    // ============================================================
    // 유틸리티
    // ============================================================

    private boolean shouldHidePath(String path) {
        if (path == null) return false;
        if (ALL_HIDDEN_PATHS.contains(path)) return true;

        String lower = path.toLowerCase();
        for (String kw : HIDDEN_PATH_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }

        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < path.length() - 1) {
            String filename = path.substring(lastSlash + 1).toLowerCase();
            if (SU_FILENAMES.contains(filename)) return true;
        }

        return false;
    }

    /**
     * su, magisk, busybox 직접 실행만 차단
     * getprop, id 등 일반 명령어는 전부 허용
     */
    private boolean isBlockedCommand(String cmd) {
        if (cmd == null) return false;
        String lower = cmd.toLowerCase().trim();

        if (lower.equals("su") || lower.startsWith("su ") || lower.startsWith("su\t")) return true;

        for (String suPath : ROOT_PATHS) {
            if (suPath.endsWith("/su") && lower.startsWith(suPath)) return true;
        }

        if (lower.contains("which su") || lower.contains("type su") || lower.contains("whereis su")) return true;

        if (lower.equals("magisk") || lower.startsWith("magisk ") ||
                lower.contains("/magisk") || lower.contains("magiskhide")) return true;

        if (lower.equals("busybox") || lower.startsWith("busybox ")) return true;
        for (String bbPath : BUSYBOX_PATHS) {
            if (lower.startsWith(bbPath)) return true;
        }

        return false;
    }

    /**
     * Frida 관련 라이브러리인지 체크 (System.load 절대경로 전용)
     */
    private boolean isFridaLibrary(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String kw : FRIDA_LIB_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    private String filterProp(String key, String value) {
        if (key == null) return value;
        switch (key) {
            case "ro.debuggable":    return "0";
            case "ro.secure":        return "1";
            case "ro.build.selinux": return "1";
            case "ro.build.tags":    return "release-keys";
            case "ro.build.type":    return "user";
            default:
                if (key.contains("magisk") || key.contains("supersu")) return "";
                return value;
        }
    }
}