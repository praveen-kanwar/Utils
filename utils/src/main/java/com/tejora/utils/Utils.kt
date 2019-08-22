package com.tejora.utils

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.util.Base64
import android.util.Log
import android.util.Patterns
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
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


private val TAG = Utils::class.java.simpleName

/**
 * Context Should Be Of Application For Correct & Optimal Performance
 */
@Singleton
class Utils
@Inject
constructor(private val context: Context) {

    /* To Hide Keyboard */
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

    /**
     *  To Check Email Pattern
     */
    @Suppress("unused")
    fun isValidEmail(email: String): Boolean {
        showLog(TAG, "isValidEmail($email)")
        return Patterns.EMAIL_ADDRESS.matcher(email)
            .matches()
    }

    /**
     *  To Check If Network Is Available or not
     */
    @Suppress("unused")
    fun isNetworkAvailable(): Boolean {
        showLog(TAG, "isNetworkAvailable($context)")
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networkInfo = cm.activeNetworkInfo
        return networkInfo != null && networkInfo.isConnected
    }

    /**
     *  Return True If Build Is [DEBUG] Type.
     *  Return False If Build Is [RELEASE] Type.
     */
    fun isApplicationDebuggable(): Boolean {
        try {
            // Get Package Name, Also Remove If uat or sandbox is appended.
            val packageName = context.packageName
                .replace(".uat", "", true)
                .replace(".sandbox", "", true)
                .plus(".BuildConfig")
            val clazz = Class.forName(packageName)
            val field = clazz.getField(DEBUG)
            return field.get(null) != null
        } catch (e: ClassNotFoundException) {
            e.printStackTrace()
        } catch (e: NoSuchFieldException) {
            e.printStackTrace()
        } catch (e: IllegalAccessException) {
            e.printStackTrace()
        }
        return false
    }

    /**
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
                        File(newFile.parent).mkdirs()
                        val fos = FileOutputStream(newFile)
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

    /**
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

    /**
     *  Detect App Signature
     *  Return 1 If Genuine
     *  Return 2 If Non-Genuine
     *  Return 3 If Unable To Verify
     */
    @Suppress("unused", "PackageManagerGetSignatures", "DEPRECATION")
    fun isApplicationSignatureValid(actualSignature: String): Observable<Int> {
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
                    //compare signatures
                    if (actualSignature == currentSignature) {
                        // Emitting
                        it.onNext(VALID_APPLICATION)
                        // Completing
                        it.onComplete()
                    } else {
                        // Emitting
                        it.onNext(INVALID_APPLICATION)
                        // Completing
                        it.onComplete()
                    }

                }
            } catch (error: Exception) {
                showLog(TAG, "Error Occurred While Checking Application Is Genuine Or Not.")
                //it.onError(error)
                // Emitting
                it.onNext(UNABLE_TO_VERIFY_APPLICATION)
                // Completing
                it.onComplete()
            }
        }
    }

    /**
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

    /**
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

    companion object {
        const val DEBUG = "DEBUG"
        const val RELEASE = "RELEASE"
        const val GOOGLE_PLAY_STORE_INSTALLER = "com.android.vending"
        const val VALID_APPLICATION = 1
        const val INVALID_APPLICATION = 2
        const val UNABLE_TO_VERIFY_APPLICATION = 3
    }
}