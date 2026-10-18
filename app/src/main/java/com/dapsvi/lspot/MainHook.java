package com.dapsvi.lspot;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "LSpot";
    private static final String TARGET = "com.spotify.music";

    private static final Set<String> BLOCKED_DOMAINS = new HashSet<>(Arrays.asList(
        "ads.spotify.com",
        "audio-ak-spotify-com.akamaized.net",
        "audio2.spotify.com",
        "adstats.spotify.com",
        "adeventtracker.spotify.com",
        "sponsored-recommendations.spotify.com",
        "desktop.spotify.com",
        "weblb-wg.gslb.spotify.com",
        "redirect.spotify.net",
        "analytics.spotify.com",
        "tracking.spotify.com",
        "log.spotify.com",
        "crashdump.spotify.com",
        "dealer.g2.spotify.com",
        "gew1-dealer.g2.spotify.com",
        "gew1-dealer-ssl.spotify.com",
        "pagead2.googlesyndication.com",
        "bs.serving-sys.com",
        "bounceexchange.com",
        "sb.scorecardresearch.com",
        "b.scorecardresearch.com",
        "video-fa.scdn.co",
        "audio-fa.scdn.co"
    ));

    private static final String[] BLOCKED_URL_KEYWORDS = {
        "/ads/",
        "/ad-logic/",
        "/ad-monetization/",
        "/v1/ads/",
        "/v2/ads/",
        "/v3/ads/",
        "/ads?",
        "/ad-express-service/",
        "/ad-feedback-service/",
        "/ad-sponsor-service/",
        "/ad-experience-service/",
        "/commercial-break/",
        "/audio-ad-reward/",
        "/gabo-receiver-service/",
        "/in-app-messages/",
        "/desktop-omni-ads/",
        "ads.spotify.com",
        "adstats.spotify.com",
        "adeventtracker.spotify.com",
        "video-fa.scdn.co",
        "audio-fa.scdn.co",
        "spotify:ad:"
    };

    private static boolean isBlockedHost(String host) {
        if (host == null) return false;
        String h = host.toLowerCase();
        for (String d : BLOCKED_DOMAINS) {
            if (h.equals(d) || h.endsWith("." + d)) return true;
        }
        return false;
    }

    private static boolean isBlockedUrl(String url) {
        if (url == null) return false;
        String u = url.toLowerCase();
        for (String kw : BLOCKED_URL_KEYWORDS) {
            if (u.contains(kw)) return true;
        }
        return false;
    }

    private static String getRequestUrl(Object request) {
        if (request == null) return null;

        // 1. Inspect fields of type okhttp3.HttpUrl
        try {
            Class<?> c = request.getClass();
            while (c != null && c != Object.class) {
                for (Field f : c.getDeclaredFields()) {
                    if (f.getType().getName().endsWith("HttpUrl")) {
                        f.setAccessible(true);
                        Object val = f.get(request);
                        if (val != null) return val.toString();
                    }
                }
                c = c.getSuperclass();
            }
        } catch (Throwable ignored) {}

        // 2. Parse from toString(): Request{method=GET, url=https://...}
        try {
            String s = request.toString();
            if (s != null && s.contains("url=")) {
                int start = s.indexOf("url=") + 4;
                int end = s.indexOf(',', start);
                if (end == -1) end = s.indexOf('}', start);
                if (end > start) return s.substring(start, end).trim();
            }
        } catch (Throwable ignored) {}

        // 3. Fallback to any 0-arg method returning HttpUrl
        try {
            for (Method m : request.getClass().getMethods()) {
                if (m.getReturnType().getName().endsWith("HttpUrl") && m.getParameterCount() == 0) {
                    m.setAccessible(true);
                    Object val = m.invoke(request);
                    if (val != null) return val.toString();
                }
            }
        } catch (Throwable ignored) {}

        return request.toString();
    }

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        if (!TARGET.equals(lpparam.packageName)) return;

        XposedBridge.log(TAG + ": Initializing hooks for " + lpparam.packageName);

        // ══════════════════════════════════════════════════════════════
        // LAYER 1: DNS Resolution Sinkhole (Ad domains -> 127.0.0.1)
        // ══════════════════════════════════════════════════════════════
        try {
            Method mAll = InetAddress.class.getMethod("getAllByName", String.class);
            XposedBridge.hookMethod(mAll, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String host = (String) param.args[0];
                    if (isBlockedHost(host)) {
                        Log.i(TAG, "DNS BLOCKED getAllByName: " + host);
                        try {
                            InetAddress loopback = InetAddress.getByAddress(host, new byte[]{127, 0, 0, 1});
                            param.setResult(new InetAddress[]{loopback});
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedBridge.log(TAG + ": Hooked InetAddress.getAllByName");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": InetAddress.getAllByName error: " + t.getMessage());
        }

        try {
            Method mOne = InetAddress.class.getMethod("getByName", String.class);
            XposedBridge.hookMethod(mOne, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String host = (String) param.args[0];
                    if (isBlockedHost(host)) {
                        Log.i(TAG, "DNS BLOCKED getByName: " + host);
                        try {
                            InetAddress loopback = InetAddress.getByAddress(host, new byte[]{127, 0, 0, 1});
                            param.setResult(loopback);
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedBridge.log(TAG + ": Hooked InetAddress.getByName");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": InetAddress.getByName error: " + t.getMessage());
        }

        try {
            Class<?> dnsClass = lpparam.classLoader.loadClass("okhttp3.Dns");
            Object systemDns = dnsClass.getField("SYSTEM").get(null);
            if (systemDns != null) {
                Method lookup = systemDns.getClass().getMethod("lookup", String.class);
                XposedBridge.hookMethod(lookup, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String host = (String) param.args[0];
                        if (isBlockedHost(host)) {
                            Log.i(TAG, "OkHttp Dns BLOCKED: " + host);
                            try {
                                InetAddress loopback = InetAddress.getByAddress(host, new byte[]{127, 0, 0, 1});
                                param.setResult(Collections.singletonList(loopback));
                            } catch (Throwable ignored) {}
                        }
                    }
                });
                XposedBridge.log(TAG + ": Hooked OkHttp Dns.SYSTEM.lookup");
            }
        } catch (Throwable ignored) {}

        // ══════════════════════════════════════════════════════════════
        // LAYER 2: URL Connection Fallback
        // ══════════════════════════════════════════════════════════════
        try {
            Method openConn = URL.class.getMethod("openConnection");
            XposedBridge.hookMethod(openConn, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    URL u = (URL) param.thisObject;
                    if (u != null && isBlockedHost(u.getHost())) {
                        Log.i(TAG, "URL.openConnection BLOCKED: " + u);
                        param.setThrowable(new IOException("Blocked ad host: " + u.getHost()));
                    }
                }
            });
            XposedBridge.log(TAG + ": Hooked URL.openConnection");
        } catch (Throwable ignored) {}

        // ══════════════════════════════════════════════════════════════
        // LAYER 3: OkHttp Request Interception (RealInterceptorChain & Chain)
        // ══════════════════════════════════════════════════════════════
        try {
            Class<?> reqClass = lpparam.classLoader.loadClass("okhttp3.Request");
            Class<?> ricClass = lpparam.classLoader.loadClass("okhttp3.internal.http.RealInterceptorChain");

            for (Method m : ricClass.getDeclaredMethods()) {
                if (m.getParameterCount() == 1
                    && m.getParameterTypes()[0].equals(reqClass)
                    && "okhttp3.Response".equals(m.getReturnType().getName())
                    && !m.getName().startsWith("lambda$")) {

                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                Object request = param.args[0];
                                if (request == null) return;
                                String url = getRequestUrl(request);
                                if (url != null && isBlockedUrl(url)) {
                                    Log.i(TAG, "OkHttp Request BLOCKED: " + url);
                                    Object empty = emptyResponse(request, lpparam.classLoader);
                                    if (empty != null) {
                                        param.setResult(empty);
                                    } else {
                                        param.setThrowable(new IOException("Blocked by LSpot: " + url));
                                    }
                                }
                            } catch (Throwable t) {
                                Log.w(TAG, "RIC check error: " + t);
                            }
                        }
                    });
                    XposedBridge.log(TAG + ": Hooked RealInterceptorChain." + m.getName() + "()");
                }
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": RealInterceptorChain hook failed: " + t.getMessage());
        }

        try {
            Class<?> reqClass = lpparam.classLoader.loadClass("okhttp3.Request");
            Class<?> chainClass = lpparam.classLoader.loadClass("okhttp3.Interceptor$Chain");
            Method proceed = chainClass.getMethod("proceed", reqClass);
            XposedBridge.hookMethod(proceed, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        Object request = param.args[0];
                        if (request == null) return;
                        String url = getRequestUrl(request);
                        if (url != null && isBlockedUrl(url)) {
                            Log.i(TAG, "Chain.proceed BLOCKED: " + url);
                            Object empty = emptyResponse(request, lpparam.classLoader);
                            if (empty != null) {
                                param.setResult(empty);
                            } else {
                                param.setThrowable(new IOException("Blocked by LSpot: " + url));
                            }
                        }
                    } catch (Throwable t) {
                        Log.w(TAG, "Chain.proceed check error: " + t);
                    }
                }
            });
            XposedBridge.log(TAG + ": Hooked Interceptor.Chain.proceed()");
        } catch (Throwable ignored) {}


        XposedBridge.log(TAG + ": All LSpot hooks successfully registered");
    }



    private static Object emptyResponse(Object request, ClassLoader cl) {
        try {
            Class<?> respClass = cl.loadClass("okhttp3.Response");
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Object unsafe = theUnsafe.get(null);
            java.lang.reflect.Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
            Object resp = allocateInstance.invoke(unsafe, respClass);

            setField(resp, "a", request);
            setField(resp, "c", "OK");
            setField(resp, "d", 204);
            return resp;
        } catch (Throwable t) {
            return null;
        }
    }

    private static void setField(Object obj, String name, Object val) {
        try {
            Class<?> c = obj.getClass();
            while (c != null && c != Object.class) {
                try {
                    Field f = c.getDeclaredField(name);
                    f.setAccessible(true);
                    f.set(obj, val);
                    return;
                } catch (NoSuchFieldException e) {
                    c = c.getSuperclass();
                }
            }
        } catch (Throwable ignored) {}
    }
}
