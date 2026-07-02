package com.jpwreach.lsposed

import android.app.Activity
import android.content.Context
import android.location.Location
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.Toast
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage

/**
 * JPW Auto-Reach LSPosed module.
 *
 * Hooks on com.jio.jpss (Jio Partner World v2.1.0) to bypass:
 *   1. Root detection (RootBeer + manual SU checks)
 *   2. Mock location detection (Location.isFromMockProvider + Settings.Secure)
 *   3. Developer Options detection (Settings.Global.development_settings_enabled)
 *   4. OTP step (SendOtp / VerifyOtp asynctasks force-success)
 *
 * Bonus: injects "AUTO-REACH ALL" floating button into MainActivity.
 */
class JpwHook : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "JpwHook"
        private const val TARGET_PKG = "com.jio.jpss"
        private fun log(s: String) = XposedBridge.log("[$TAG] $s")
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PKG) return
        log("Loaded into ${lpparam.packageName}")

        val cl = lpparam.classLoader

        // ── 1. Mock-Location & Dev-Settings system-level bypass ──
        bypassMockLocation()
        bypassDeveloperSettings()

        // ── 2. RootBeer / SU detection bypass ──
        bypassRootBeer(cl)

        // ── 3. AppSecurityModule check methods bypass ──
        bypassAppSecurityModule(cl)

        // ── 4. OTP flow bypass (SendOtp / VerifyOtp) ──
        bypassOtpFlow(cl)

        // ── 5. Inject Auto-Reach FAB into MainActivity ──
        injectAutoReachButton(cl)

        // ── 6. SIM verification bypass (TelephonyManager) ──
        bypassSimVerification(cl)

        // ── 7. App signature + integrity check bypass ──
        bypassSignatureAndIntegrity(cl)
    }

    // ─── 1. Mock location → always false ───
    private fun bypassMockLocation() {
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isFromMockProvider",
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked Location.isFromMockProvider → false")
        } catch (t: Throwable) { log("✗ isFromMockProvider: $t") }

        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isMock",
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked Location.isMock → false")
        } catch (_: Throwable) {}

        // Settings.Secure.getInt with "mock_location" / "ALLOW_MOCK_LOCATION" → 0
        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getInt",
                android.content.ContentResolver::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val k = p.args[1] as String?
                        if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") {
                            p.result = 0
                        }
                    }
                }
            )
            log("✓ Hooked Settings.Secure.getInt mock_location → 0")
        } catch (t: Throwable) { log("✗ Settings.Secure 2-arg: $t") }

        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getInt",
                android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val k = p.args[1] as String?
                        if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") {
                            p.result = 0
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }

    // ─── 2. Developer options & ADB → 0 ───
    private fun bypassDeveloperSettings() {
        val hook = object : XC_MethodHook() {
            override fun beforeHookedMethod(p: MethodHookParam) {
                val k = p.args[1] as String?
                if (k == "development_settings_enabled" || k == "adb_enabled") {
                    p.result = 0
                }
            }
        }
        for (klass in listOf(Settings.Global::class.java, Settings.Secure::class.java, Settings.System::class.java)) {
            for (sig in listOf(
                arrayOf(android.content.ContentResolver::class.java, String::class.java),
                arrayOf(android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType),
            )) {
                try { XposedHelpers.findAndHookMethod(klass, "getInt", *sig, hook) } catch (_: Throwable) {}
            }
        }
        log("✓ Hooked Settings.*.getInt dev/adb → 0")
    }

    // ─── 3. RootBeer + SU checks → false ───
    private fun bypassRootBeer(cl: ClassLoader) {
        val rootBeerNames = listOf(
            "com.scottyab.rootbeer.RootBeer",
            "com.scottyab.rootbeer.RootBeerNative",
        )
        for (clsName in rootBeerNames) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                // Hook every public method returning boolean → false
                cls.declaredMethods.forEach { m ->
                    if (m.returnType == Boolean::class.javaPrimitiveType) {
                        try {
                            XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false))
                        } catch (_: Throwable) {}
                    }
                }
                log("✓ Hooked $clsName (all boolean methods → false)")
            } catch (_: Throwable) {
                log("ℹ $clsName not present")
            }
        }
    }

    // ─── 4. AppSecurityModule check methods bypass ───
    private fun bypassAppSecurityModule(cl: ClassLoader) {
        val classes = listOf(
            "com.jio.jpss.AppSecurityModule",
            "com.jio.jpss.AppSecurityModule\$Companion",
        )
        val matchKeywords = listOf(
            "isRoot", "checkRoot", "isMock", "checkMock", "isDevelop", "checkDevelop",
            "isEmulator", "checkEmulator", "isDebugger", "checkDebugger",
            "verifyOtp", "isOtpRequired", "needOtp", "isVerified", "checkOtp"
        )
        for (clsName in classes) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                cls.declaredMethods.forEach { m ->
                    val name = m.name
                    val matches = matchKeywords.any { name.contains(it, ignoreCase = true) }
                    if (!matches) return@forEach
                    try {
                        val rt = m.returnType
                        val replacement = when {
                            rt == Boolean::class.javaPrimitiveType ->
                                // verify/isVerified should be true; everything else false
                                if (name.contains("verify", true) || name.contains("isVerified", true))
                                    XC_MethodReplacement.returnConstant(true)
                                else XC_MethodReplacement.returnConstant(false)
                            rt == Int::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(0)
                            rt == String::class.java ->
                                XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, replacement)
                        log("✓ Hooked $clsName.$name → bypass")
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {
                log("ℹ $clsName not present")
            }
        }
    }

    // ─── 5. OTP flow short-circuit ───
    private fun bypassOtpFlow(cl: ClassLoader) {
        // Force VerifyOtp / SendOtp asynctasks to silently succeed without server call.
        val targets = listOf(
            "com.jio.jpss.asynctask.SendOtp",
            "com.jio.jpss.asynctask.VerifyOtp",
        )
        for (t in targets) {
            try {
                val cls = XposedHelpers.findClass(t, cl)
                // Override doInBackground to return a fake-success object
                cls.declaredMethods.forEach { m ->
                    if (m.name == "doInBackground") {
                        try {
                            XposedBridge.hookMethod(m, object : XC_MethodReplacement() {
                                override fun replaceHookedMethod(p: MethodHookParam): Any? {
                                    log("OTP shortcircuit: $t.doInBackground returning fake-success")
                                    // Return a JSONObject string the app probably expects
                                    return """{"IsSuccessful":true,"Status":"VERIFIED","Message":"OK"}"""
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                    if (m.name == "onPostExecute") {
                        try {
                            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                                override fun beforeHookedMethod(p: MethodHookParam) {
                                    log("OTP onPostExecute called for $t — letting through")
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
                log("✓ Hooked $t (OTP shortcircuit)")
            } catch (_: Throwable) {
                log("ℹ $t not present")
            }
        }
    }

    // ─── 6. Inject Auto-Reach floating button ───
    private fun injectAutoReachButton(cl: ClassLoader) {
        try {
            val mainCls = XposedHelpers.findClass("com.jio.jpss.MainActivity", cl)
            XposedHelpers.findAndHookMethod(
                mainCls, "onCreate", Bundle::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        val act = p.thisObject as Activity
                        addFab(act)
                    }
                }
            )
            log("✓ Hooked MainActivity.onCreate (FAB inject)")
        } catch (t: Throwable) {
            log("✗ FAB inject failed: $t")
        }
    }

    private fun addFab(activity: Activity) {
        try {
            activity.window.decorView.post {
                val root = activity.findViewById<FrameLayout>(android.R.id.content)
                if (root == null || root.findViewWithTag<View>("jpw_auto_reach_fab") != null) return@post

                val ctx = activity
                val fab = android.widget.Button(ctx).apply {
                    text = "⚡ AUTO-REACH"
                    setTextColor(android.graphics.Color.WHITE)
                    textSize = 13f
                    setPadding(dp(ctx, 16), dp(ctx, 10), dp(ctx, 16), dp(ctx, 10))
                    background = makeRedGradient(ctx)
                    elevation = dp(ctx, 8).toFloat()
                    tag = "jpw_auto_reach_fab"
                    setOnClickListener { onAutoReachClicked(ctx) }
                }
                val lp = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    gravity = Gravity.BOTTOM or Gravity.END
                    rightMargin = dp(ctx, 16)
                    bottomMargin = dp(ctx, 24)
                }
                root.addView(fab, lp)
                log("✓ AUTO-REACH button injected into MainActivity")
            }
        } catch (t: Throwable) {
            log("addFab failed: $t")
        }
    }

    private fun onAutoReachClicked(ctx: Context) {
        Toast.makeText(ctx,
            "Auto-Reach: launching companion service…",
            Toast.LENGTH_SHORT).show()
        try {
            // Capture session cookies from WebView / CookieManager
            val cookies = try {
                android.webkit.CookieManager.getInstance().getCookie("https://jpw.jio.com")
            } catch (_: Throwable) { null }
            val jioCenterId = try {
                val prefs = ctx.getSharedPreferences("com.jio.jpss_preferences", Context.MODE_PRIVATE)
                prefs.getString("jio_center_id", "") ?: ""
            } catch (_: Throwable) { "" }

            val intent = ctx.packageManager
                .getLaunchIntentForPackage("com.jpwreach.auto")
            if (intent != null) {
                if (cookies != null) intent.putExtra("cookies", cookies)
                if (jioCenterId.isNotEmpty()) intent.putExtra("jio_center_id", jioCenterId)
                ctx.startActivity(intent)
            } else {
                Toast.makeText(ctx,
                    "Install JPW Auto-Reach Companion app first",
                    Toast.LENGTH_LONG).show()
            }
        } catch (t: Throwable) {
            Toast.makeText(ctx, "Error: ${t.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun dp(ctx: Context, v: Int): Int =
        (v * ctx.resources.displayMetrics.density).toInt()

    // ─── 7. App signature + Play Integrity bypass ───
    private fun bypassSignatureAndIntegrity(cl: ClassLoader) {
        // 1. CommonUtility.checkAPKInstallationValidation → false (not cloned)
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.utils.CommonUtility",
                cl, "checkAPKInstallationValidation",
                Context::class.java,
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked CommonUtility.checkAPKInstallationValidation → false")
        } catch (t: Throwable) { log("✗ checkAPKInstallation: $t") }

        // 2. CommonUtility.checkIfAppCloned → false
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.utils.CommonUtility",
                cl, "checkIfAppCloned",
                Context::class.java, String::class.java,
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked CommonUtility.checkIfAppCloned → false")
        } catch (t: Throwable) { log("✗ checkIfAppCloned: $t") }

        // 3. AppSignatureHelper.getAppSignatures → null (bypass hash check)
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.AppSignatureHelper",
                cl, "getAppSignatures",
                XC_MethodReplacement.returnConstant(null)
            )
            log("✓ Hooked AppSignatureHelper.getAppSignatures → null")
        } catch (t: Throwable) { log("✗ AppSignatureHelper: $t") }

        // 4. CommonUtility.getSigningCertSha256 → return expected hash
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.utils.CommonUtility",
                cl, "getSigningCertSha256",
                Context::class.java,
                XC_MethodReplacement.returnConstant(
                    "dba24e5c252891027c96b8d21b1659dad47219f5d4e0be0bd898640509ca380c"
                )
            )
            log("✓ Hooked getSigningCertSha256 → original Jio cert hash")
        } catch (t: Throwable) { log("✗ getSigningCertSha256: $t") }

        // 5. ValidateAppCheckAsyncTask → neutralized (sends clone metadata to server)
        try {
            val vac = XposedHelpers.findClass("com.jio.jpss.asynctask.ValidateAppCheckAsyncTask", cl)
            vac.declaredMethods.forEach { m ->
                if (m.name == "doInBackground") {
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null))
                }
                if (m.name == "onPostExecute") {
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null))
                }
            }
            log("✓ Hooked ValidateAppCheckAsyncTask → neutralized")
        } catch (t: Throwable) { log("✗ ValidateAppCheckAsyncTask: $t") }

        // 6. AppSecurityModule.getAppIntegrityToken → properly bypass
        try {
            val promiseClass = XposedHelpers.findClass("com.facebook.react.bridge.Promise", cl)
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.AppSecurityModule",
                cl, "getAppIntegrityToken",
                promiseClass,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(p: MethodHookParam): Any? {
                        try {
                            val promise = p.args[0] ?: return null
                            // Resolve promise with empty integrity token using reflection
                            val argumentsClass = XposedHelpers.findClass("com.facebook.react.bridge.Arguments", cl)
                            val map = XposedHelpers.callStaticMethod(argumentsClass, "createMap")
                            XposedHelpers.callMethod(map, "putString", "integrityToken", "")
                            XposedHelpers.callMethod(promise, "resolve", map)
                            log("✓ getAppIntegrityToken → resolved with empty token")
                        } catch (e: Throwable) {
                            log("✗ getAppIntegrityToken promise error: $e")
                            try {
                                val promise = p.args[0] ?: return null
                                XposedHelpers.callMethod(promise, "reject", "BYPASS", "Integrity bypassed")
                            } catch (_: Throwable) {}
                        }
                        return null
                    }
                }
            )
            log("✓ Hooked AppSecurityModule.getAppIntegrityToken → bypassed properly")
        } catch (t: Throwable) { log("✗ getAppIntegrityToken: $t") }
    }

    // ─── 8. SIM verification bypass ───
    private fun bypassSimVerification(cl: ClassLoader) {
        // Hook TelephonyManager methods → Jio cannot fingerprint your SIM
        try {
            val tm = Class.forName("android.telephony.TelephonyManager")
            val noopFalse = XC_MethodReplacement.returnConstant(false)
            val noopNull  = XC_MethodReplacement.returnConstant(null)
            val noopZero  = XC_MethodReplacement.returnConstant(0)
            val noopEmpty = XC_MethodReplacement.returnConstant("")

            // Methods returning sensitive identifiers — neutralise them
            val emptyStringMethods = listOf(
                "getSubscriberId",         // IMSI
                "getLine1Number",          // Phone number
                "getSimSerialNumber",      // ICCID
                "getDeviceId",             // IMEI
                "getImei",                 // IMEI (newer)
                "getMeid",                 // CDMA MEID
                "getSimOperator",
                "getSimOperatorName",
                "getNetworkOperator",
                "getNetworkOperatorName",
                "getSimCountryIso",
                "getNetworkCountryIso",
            )
            for (mName in emptyStringMethods) {
                tm.declaredMethods.filter { it.name == mName }.forEach { m ->
                    try {
                        XposedBridge.hookMethod(m, noopEmpty)
                    } catch (_: Throwable) {}
                }
            }
            // Methods returning booleans about SIM state → false
            val booleanMethods = listOf("hasIccCard", "isNetworkRoaming", "isDataEnabled")
            for (mName in booleanMethods) {
                tm.declaredMethods.filter { it.name == mName }.forEach { m ->
                    try { XposedBridge.hookMethod(m, noopFalse) } catch (_: Throwable) {}
                }
            }
            // getSimState → 5 (SIM_STATE_READY) so the app thinks SIM is fine
            try {
                tm.declaredMethods.filter { it.name == "getSimState" }.forEach { m ->
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(5))
                }
            } catch (_: Throwable) {}

            log("✓ TelephonyManager SIM identifiers spoofed")
        } catch (t: Throwable) {
            log("✗ SIM bypass setup: $t")
        }

        // Also hook Jio app's internal SIM verification methods (keyword-based)
        val simKeywords = listOf(
            "verifySim", "validateSim", "isSimValid", "checkSim", "matchSim",
            "isSimRegistered", "validatePhone", "verifyPhone", "isPhoneValid",
            "isMobileMatched", "matchPhoneNumber", "phoneVerification"
        )
        val candidateClasses = listOf(
            "com.jio.jpss.AppSecurityModule",
            "com.jio.jpss.AppSecurityModule\$Companion",
            "com.jio.jpss.utility.SimVerifier",
            "com.jio.jpss.utility.PhoneVerifier",
            "com.jio.jpss.NativeHandler",
        )
        for (clsName in candidateClasses) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                cls.declaredMethods.forEach { m ->
                    val matches = simKeywords.any { m.name.contains(it, ignoreCase = true) }
                    if (!matches) return@forEach
                    try {
                        val rt = m.returnType
                        val replacement = when (rt) {
                            Boolean::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(true)
                            Int::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(0)
                            String::class.java ->
                                XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, replacement)
                        log("✓ Hooked $clsName.${m.name} → SIM bypass")
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {
                // class not present in this build — ignore
            }
        }
    }

    private fun makeRedGradient(ctx: Context): android.graphics.drawable.GradientDrawable {
        val d = android.graphics.drawable.GradientDrawable(
            android.graphics.drawable.GradientDrawable.Orientation.TL_BR,
            intArrayOf(0xFFe60012.toInt(), 0xFFff3a44.toInt())
        )
        d.cornerRadius = dp(ctx, 28).toFloat()
        return d
    }
}
