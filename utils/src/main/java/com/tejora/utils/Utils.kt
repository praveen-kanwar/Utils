package com.tejora.utils

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.Base64
import android.util.Log
import android.util.Patterns
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.core.app.ActivityCompat
import com.scottyab.rootbeer.RootBeer
import io.reactivex.Observable
import io.reactivex.disposables.Disposable
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Context Should Be Of Application For Correct & Optimal Performance
 */
@Suppress("unused")
@Singleton
class Utils
@Inject
constructor(private val context: Context) : ConnectivityManager.NetworkCallback() {

    private var enableLog = false

    private var isInternetAvailable = false

    /*
     * This Method Will Be Called When Network Connectivity Is Lost
     */
    override fun onLost(network: Network?) {
        showLog(TAG, "Internet Connectivity Lost.")
        isInternetAvailable = false
        // Further Can Be Evaluated To Check If WiFi Lost Event
    }

    /*
     * This Method Will Be Called When Network Connectivity Is Unavailable
     */
    override fun onUnavailable() {
        showLog(TAG, "Internet Unavailable.")
        isInternetAvailable = false
    }

    /*
     * This Method Will Be Called When Network Connectivity Is Losing.
     */
    override fun onLosing(network: Network?, maxMsToLive: Int) {
        showLog(TAG, "Internet Connectivity Losing.")
        isInternetAvailable = false
    }

    /*
     * This Method Will Be Called When Network Connectivity Is Available
     */
    override fun onAvailable(network: Network?) {
        showLog(TAG, "Internet Available.")
        isInternetAvailable = true
        // Further Can Be Evaluated To Check If WiFi Available.
    }

    /* To Enable/Disable Logs */
    @Suppress("unused")
    fun enableLog(enableLog: Boolean) {
        this.enableLog = enableLog
    }


    /* To Get Application Context */
    @Suppress("unused")
    fun getMainApplicationContext(): Context {
        return context
    }

    /* To Log In Debug Build */
    @Suppress("unused")
    fun showLog(TAG: String, message: String) {
        try {
            if (isApplicationDebuggable()) {
                Log.e(TAG, message)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /* To Show Toast */
    @Suppress("unused")
    fun showToast(message: String) {
        showLog(TAG, "showToast($context, $message)")
        try {
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * To Display Dialog With User Provided Values.
     *
     * [TejoraBus].listen Return [Disposable]
     * [Disposable] = [TejoraBus].listen([TejoraDialogResponse]::class.java).subscribe { response -> //Code }
     * Don't Forget To Dispose Disposable On onPause Method
     * if (![Disposable].isDisposed) [Disposable].dispose()
     */
    @Suppress("unused")
    fun showDialog(
        activity: Activity, // As Dialog Can Be Displayed Over Activity Hence Activity Context Or Activity Is Required.
        pageName: String = "", //Fragment/Activity Where Dialog Is Displayed
        reasonForDisplay: String = "", //Reason To Display Dialog.
        title: String? = null, // Dialog Title
        message: String = "", //Message To Be Displayed..
        cancelMessage: String? = null, // Cancel/Negative Button Text
        okayMessage: String = "Okay" // Okay/Positive Button Text
    ) {
        try {
            // Creating Default Response
            val response = TejoraDialogResponse(
                pageName,
                reasonForDisplay,
                title,
                message,
                cancelMessage,
                okayMessage
            )
            activity.let { suppliedActivity ->
                val alertDialog =
                    AlertDialog.Builder(suppliedActivity) // Create Alert Dialog Builder
                if (title != null) {
                    alertDialog.setTitle(title) // Set Title If Supplied
                }
                alertDialog.setMessage(message) // Set Message
                // Set Positive Button
                alertDialog.setPositiveButton(okayMessage) { dialog, _ ->
                    response.userOpted = okayMessage // Set User Opted Acceptance
                    TejoraBus.publish(response) // Publish User Selection
                    dialog.dismiss() // Dismiss Dialog
                }
                // Set Negative Button If Supplied/Required As Per User Requirement
                if (cancelMessage != null) {
                    alertDialog.setNegativeButton(cancelMessage) { dialog, _ ->
                        response.userOpted = cancelMessage // Set User Opted For Rejection
                        TejoraBus.publish(response) // Publish User Selection
                        dialog.dismiss() // Dismiss Dialog
                    }
                }
                alertDialog.create().show() // Display Dialog
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /* To Hide Keyboard */
    @Suppress("unused")
    fun hideKeyboard(editText: EditText) {
        editText.clearFocus()
        (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(
            editText.windowToken,
            0
        )
    }

    /* To Show Keyboard */
    @Suppress("unused")
    fun showKeyboard(editText: EditText) {
        editText.requestFocus()
        (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).showSoftInput(
            editText,
            InputMethodManager.SHOW_IMPLICIT
        )
        editText.setSelection(editText.text.toString().length)
    }

    /* To Get Application Context */
    @Suppress("unused")
    fun isAutoTimeEnabled(): Observable<Boolean> {
        return Observable.create {
            try {
                // Emitting
                it.onNext(
                    (Settings.Global.getInt(
                        context.contentResolver,
                        Settings.Global.AUTO_TIME,
                        0
                    ) == 1)
                )
                // Completing
                it.onComplete()
            } catch (error: Exception) {
                it.onError(error)
            }
        }
    }

    /*
     * This Method Will Return Device International Mobile Equipment Identity.
     */
    fun getDeviceIMEI(): String {
        val telephonyManager =
            context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getDeviceIMEIPostOreo(telephonyManager)
        } else {
            getDeviceIMEIPreOreo(telephonyManager)
        }
    }

    /*
     * This Method Will Return Device International Mobile Equipment Identity.
     */
    @SuppressLint("HardwareIds")
    @RequiresApi(api = Build.VERSION_CODES.O)
    fun getDeviceIMEIPostOreo(telephonyManager: TelephonyManager): String {
        val deviceUniqueIdentifier = if (ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_PHONE_STATE
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            when (telephonyManager.phoneCount) {
                1 -> {
                    if (telephonyManager.imei == null) {
                        Settings.Secure.getString(
                            context.contentResolver,
                            Settings.Secure.ANDROID_ID
                        )
                    } else {
                        telephonyManager.imei
                    }
                }
                2 -> {
                    if (telephonyManager.getImei(1) == null) {
                        Settings.Secure.getString(
                            context.contentResolver,
                            Settings.Secure.ANDROID_ID
                        )
                    } else {
                        telephonyManager.getImei(1)
                    }
                }
                else -> {
                    Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
                }
            }
        } else {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        }
        showLog(TAG, "Device Unique Identifier -> $deviceUniqueIdentifier")
        return deviceUniqueIdentifier
    }

    /*
     * This Method Will Return Device International Mobile Equipment Identity.
     */
    @Suppress("DEPRECATION", "HardwareIds")
    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    fun getDeviceIMEIPreOreo(telephonyManager: TelephonyManager): String {
        val deviceUniqueIdentifier = if (ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_PHONE_STATE
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            if (telephonyManager.deviceId == null) {
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            } else {
                telephonyManager.deviceId
            }
        } else {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        }
        showLog(TAG, "Device Unique Identifier -> $deviceUniqueIdentifier")
        return deviceUniqueIdentifier
    }

    /*
     *  To Check Email Pattern
     */
    @Suppress("unused")
    fun isValidEmail(email: String): Boolean {
        showLog(TAG, "isValidEmail($email)")
        return Patterns.EMAIL_ADDRESS.matcher(email)
            .matches()
    }

    /*
     *  To Check If Network Is Available or not
     */
    @Suppress("unused")
    fun isNetworkAvailable(): Boolean {
        showLog(TAG, "isNetworkAvailable -> $isInternetAvailable")
        return isInternetAvailable
    }

    /*
     *  Return True If Build Is [DEBUG] Type As In Debug It's Debuggable.
     *  Return False If Build Is [RELEASE] Type As In Release It's Not Debuggable.
     */
    @Suppress("unused")
    fun isApplicationDebuggable(): Boolean {
        return enableLog
    }

    /*
     *  Return String Extracted From Zip File
     */
    @Suppress("unused")
    fun unzip(zipFileName: String): Observable<String> {
        return Observable.create {
            try {
                val zipFileInputStream = context.assets.open(zipFileName)
                val buffer = ByteArray(1024)
                val zis = ZipInputStream(zipFileInputStream)
                var ze: ZipEntry? = zis.nextEntry
                var newFile: File? = null
                while (ze != null) {
                    val fileName = ze.name
                    newFile = File.createTempFile(fileName, ".tmp", context.cacheDir)
                    newFile.deleteOnExit()
                    if (ze.isDirectory) {
                        newFile.mkdirs()
                    } else {
                        File(newFile.parent!!).mkdirs()
                        val fos = FileOutputStream(newFile!!)
                        var len = zis.read(buffer)
                        while (len > 0) {
                            fos.write(buffer, 0, len)
                            len = zis.read(buffer)
                        }
                        fos.close()
                    }
                    ze = zis.nextEntry
                }
                zis.closeEntry()
                zis.close()
                zipFileInputStream.close()
                // Emitting
                it.onNext(String(newFile!!.readBytes()))
                // Completing
                it.onComplete()
            } catch (error: Exception) {
                it.onError(error)
            }
        }
    }

    /*
     *  Detect Device Is Rooted Or Not
     */
    @Suppress("unused")
    fun isDeviceSafe(): Observable<Boolean> {
        return Observable.create {
            try {
                // Emitting
                it.onNext(RootBeer(context).isRootedWithoutBusyBoxCheck)
                // Completing
                it.onComplete()
            } catch (error: Exception) {
                it.onError(error)
            }
        }
    }

    /*
     *  Detect App Signature
     *  Return true If Genuine
     *  Return false If Non-Genuine
     *  Return false If Unable To Verify
     */
    @Suppress("unused", "PackageManagerGetSignatures", "DEPRECATION")
    fun isApplicationSignatureValid(actualSignature: String): Observable<Boolean> {
        return Observable.create {
            try {
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                for (signature in packageInfo.signatures) {
                    val signatureBytes = signature.toByteArray()
                    val md = MessageDigest.getInstance("SHA")
                    md.update(signatureBytes)
                    val currentSignature = Base64.encodeToString(md.digest(), Base64.DEFAULT)
                    showLog(TAG, "Application Current Signature:-> $currentSignature")
                    showLog(TAG, "Application Actual  Signature:-> $actualSignature")
                    //compare signatures
                    if (actualSignature.trim() == currentSignature.trim()) {
                        showLog(TAG, "Signature Matched")
                        // Emitting
                        it.onNext(true)
                        // Completing
                        it.onComplete()
                    } else {
                        showLog(TAG, "Signature Not Matched")
                        // Emitting
                        it.onNext(false)
                        // Completing
                        it.onComplete()
                    }
                }
            } catch (error: Exception) {
                showLog(TAG, "Unable to verify application signature.")
                //it.onError(error)
                // Emitting
                it.onNext(false)
                // Completing
                it.onComplete()
            }
        }
    }

    /*
     *  Detect If Application Is Installed Via PlayStore
     *  Return True If Installed Via PlayStore
     *  Return False If Installed Via Other Source
     */
    @Suppress("unused")
    fun isInstalledFromPlayStore(): Observable<Boolean> {
        return Observable.create {
            try {
                val installer = context.packageManager.getInstallerPackageName(context.packageName)
                val isInstalledFromPlayStore =
                    installer != null && installer.startsWith(GOOGLE_PLAY_STORE_INSTALLER)
                // Emitting
                it.onNext(isInstalledFromPlayStore)
                // Completing
                it.onComplete()
            } catch (error: Exception) {
                it.onError(error)
            }
        }
    }

    /*
     *  Detect If Application Is Running On Emulator
     *  Return True If Running On Emulator
     *  Return False If Not Running On Emulator
     */
    @Suppress("unused")
    fun isApplicationRunningOnEmulator(): Observable<Boolean> {
        return Observable.create {
            try {
                // Emitting
                it.onNext(
                    (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                            || Build.FINGERPRINT.startsWith("generic")
                            || Build.FINGERPRINT.startsWith("unknown")
                            || Build.HARDWARE.contains("goldfish")
                            || Build.HARDWARE.contains("ranchu")
                            || Build.MODEL.contains("google_sdk")
                            || Build.MODEL.contains("Emulator")
                            || Build.MODEL.contains("Android SDK built for x86")
                            || Build.MANUFACTURER.contains("Genymotion")
                            || Build.PRODUCT.contains("sdk_google")
                            || Build.PRODUCT.contains("google_sdk")
                            || Build.PRODUCT.contains("sdk")
                            || Build.PRODUCT.contains("sdk_x86")
                            || Build.PRODUCT.contains("vbox86p")
                            || Build.PRODUCT.contains("emulator")
                            || Build.PRODUCT.contains("simulator")
                )
                // Completing
                it.onComplete()
            } catch (error: Exception) {
                it.onError(error)
            }
        }
    }

    @Suppress("unused")
    companion object {
        const val TAG = "Utils"
        const val DEBUG = "DEBUG"
        const val RELEASE = "RELEASE"
        const val GOOGLE_PLAY_STORE_INSTALLER = "com.android.vending"
    }
}