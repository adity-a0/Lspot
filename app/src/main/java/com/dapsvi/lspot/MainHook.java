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

        try {
            Class<?> respClass = lpparam.classLoader.loadClass("okhttp3.Response");
            for (Method m : respClass.getDeclaredMethods()) {
                if ("close".equals(m.getName()) && m.getParameterCount() == 0) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                Object resp = param.thisObject;
                                if (resp != null) {
                                    Field f = resp.getClass().getDeclaredField("g");
                                    f.setAccessible(true);
                                    if (f.get(resp) == null) {
                                        param.setResult(null);
                                    }
                                }
                            } catch (Throwable ignored) {}
                        }
                    });
                    XposedBridge.log(TAG + ": Hooked Response.close() null-safe guard");
                }
            }
        } catch (Throwable ignored) {}

        XposedBridge.log(TAG + ": All LSpot hooks successfully registered");
    }



    private static Object emptyResponse(Object request, ClassLoader cl) {
        // Method 1: Using okhttp3.Response.Builder
        try {
            Class<?> builderClass = cl.loadClass("okhttp3.Response$Builder");
            Object builder = builderClass.getDeclaredConstructor().newInstance();

            Object protocol = null;
            try {
                Class<?> protocolClass = cl.loadClass("okhttp3.Protocol");
                Object[] protocols = (Object[]) protocolClass.getMethod("values").invoke(null);
                if (protocols != null && protocols.length > 0) {
                    protocol = protocols[0];
                    for (Object p : protocols) {
                        String ps = p.toString();
                        if (ps.contains("1.1") || ps.equalsIgnoreCase("HTTP_1_1")) {
                            protocol = p;
                            break;
                        }
                    }
                }
            } catch (Throwable ignored) {}

            setField(builder, "a", request);
            if (protocol != null) setField(builder, "b", protocol);
            setField(builder, "c", 200);
            setField(builder, "d", "OK");

            for (Method m : builderClass.getDeclaredMethods()) {
                if (m.getParameterCount() == 0 && m.getReturnType().getName().endsWith("Response")) {
                    m.setAccessible(true);
                    Object resp = m.invoke(builder);
                    if (resp != null) {
                        return resp;
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Response$Builder creation error: " + t);
        }

        // Method 2: Unsafe direct allocation fallback
        try {
            Class<?> respClass = cl.loadClass("okhttp3.Response");
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Object unsafe = theUnsafe.get(null);
            Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
            Object resp = allocateInstance.invoke(unsafe, respClass);

            Object protocol = null;
            try {
                Class<?> protocolClass = cl.loadClass("okhttp3.Protocol");
                Object[] protocols = (Object[]) protocolClass.getMethod("values").invoke(null);
                if (protocols != null && protocols.length > 0) {
                    protocol = protocols[0];
                }
            } catch (Throwable ignored) {}

            Object emptyBody = null;
            try {
                Class<?> bodyClass = cl.loadClass("okhttp3.ResponseBody");
                for (Field f : bodyClass.getDeclaredFields()) {
                    if (bodyClass.isAssignableFrom(f.getType())) {
                        f.setAccessible(true);
                        emptyBody = f.get(null);
                        if (emptyBody != null) break;
                    }
                }
            } catch (Throwable ignored) {}

            Object emptyHeaders = null;
            try {
                Class<?> headersClass = cl.loadClass("okhttp3.Headers");
                for (Field f : headersClass.getDeclaredFields()) {
                    if (headersClass.isAssignableFrom(f.getType())) {
                        f.setAccessible(true);
                        emptyHeaders = f.get(null);
                        if (emptyHeaders != null) break;
                    }
                }
            } catch (Throwable ignored) {}

            setField(resp, "a", request);
            if (protocol != null) setField(resp, "b", protocol);
            setField(resp, "c", "OK");
            setField(resp, "d", 200);
            if (emptyHeaders != null) setField(resp, "f", emptyHeaders);
            if (emptyBody != null) setField(resp, "g", emptyBody);

            return resp;
        } catch (Throwable t) {
            Log.w(TAG, "emptyResponse Unsafe fallback error: " + t);
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
