package com.tejora.utils

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.Base64
import android.util.Log
import android.util.Patterns
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.Toast
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.safetynet.SafetyNet
import com.google.gson.Gson
import com.scottyab.rootbeer.RootBeer
import com.stfalcon.smsverifycatcher.OnSmsCatchListener
import com.stfalcon.smsverifycatcher.SmsVerifyCatcher
import io.reactivex.Observable
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Context Should Be Of Application For Correct & Optimal Performance
 */
@Suppress("unused")
@Singleton
class IUtils
@Inject
constructor(
    private val context: Context,
    private val utilsDependencyProvided: UtilsDependencyProvided,
    private val gson: Gson
) : Utils {

    init {
        showLog(TAG, "Registering For Internet Availability Callbacks")
        /**
         * To Get CallBack Of Internet Connectivity.
         */
        (context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
            .registerNetworkCallback(
                NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .build(), object : ConnectivityManager.NetworkCallback() {
                    /*
                     * This Method Will Be Called When Network Connectivity Is Lost
                     */
                    override fun onLost(network: Network?) {
                        showLog(TAG, "Internet Connectivity Lost.")
                        isInternetAvailable = false
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
                    }
                }
            )
    }

    // Create a DateFormatter object for displaying date in specified format.
    private var dateFormatter = SimpleDateFormat(DEFAULT_DATE_FORMAT, Locale.ENGLISH)

    // Flag Responsible For Enable/Disable Of Log Printing In DDMS
    private var enableLog = false

    // Flag Responsible For The Status Of Internet
    private var isInternetAvailable = false

    private var smsVerifyCatcher: SmsVerifyCatcher? = null

    /**
     *  Decrypt Supplied Cipher Text.
     *  @return Clear Text Readable By Human.
     */
    override fun decryptCipherText(cipherText: String): String {
        showLog(TAG, "Decrypt Cipher Text -> $cipherText")
        val cipherTextByteArray = Base64.decode(cipherText, Base64.DEFAULT)
        showLog(TAG, "Decrypt Cipher Text ByteArray -> ${cipherTextByteArray!!.contentToString()}")
        val clearTextEncodedByteArray =
            utilsDependencyProvided.getCipherTextDecryptionCipher().doFinal(cipherTextByteArray)
        showLog(
            TAG,
            "Decrypted Encoded Clear Text ByteArray -> ${clearTextEncodedByteArray!!.contentToString()}"
        )
        val clearTextByteArray = Base64.decode(clearTextEncodedByteArray, Base64.DEFAULT)
        showLog(TAG, "Decrypted Clear Text ByteArray -> ${clearTextByteArray!!.contentToString()}")
        val clearText = String(clearTextByteArray, Charsets.UTF_8)
        showLog(TAG, "Decrypted Clear Text -> $clearText")
        return clearText
    }

    /**
     * To Enable/Disable Logs In Dalvik Debug Monitor Service.
     */
    override fun enableLog(enableLog: Boolean) {
        this.enableLog = enableLog
    }

    /**
     *  Encrypt Supplied Clear Text.
     *  @return Cipher Text Not Readable By Human.
     */
    override fun encryptClearText(clearText: String): String {
        showLog(TAG, "Encrypt Clear Text -> $clearText")
        val clearTextByteArray = clearText.toByteArray(Charsets.UTF_8)
        showLog(TAG, "Encrypt Clear Text ByteArray -> ${clearTextByteArray.contentToString()}")
        val clearTextEncodedByteArray = Base64.encode(clearTextByteArray, Base64.DEFAULT)
        showLog(
            TAG,
            "Encrypt Clear Text Encoded ByteArray -> ${clearTextEncodedByteArray!!.contentToString()}"
        )
        val cipherTextByteArray = utilsDependencyProvided.getClearTextEncryptionCipher()
            .doFinal(clearTextEncodedByteArray)
        showLog(
            TAG,
            "Encrypted Cipher Text ByteArray -> ${cipherTextByteArray!!.contentToString()}"
        )
        val cipherTextString = Base64.encodeToString(cipherTextByteArray, Base64.DEFAULT)
        showLog(TAG, "Encrypted Cipher Text -> $cipherTextString")
        return cipherTextString
    }

    /**
     *  To Fetch Unique Database Key, Responsible For Database Encryption.
     *  @return [ByteArray] To Encrypt Database.
     */
    override fun fetchDatabaseEncryptionKey(): ByteArray {
        return utilsDependencyProvided.fetchDatabaseEncryptionKey()
    }

    /**
     * To Fetch Device International Mobile Equipment Identity (IMEI).
     * @return IMEI In [String] Format Of Device.
     */
    override fun fetchDeviceIMEI(): String {
        val telephonyManager =
            context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            utilsDependencyProvided.getDeviceIMEIPostOreo(telephonyManager)
        } else {
            utilsDependencyProvided.getDeviceIMEIPreOreo(telephonyManager)
        }
    }

    /**
     * To Fetch Context Of Application
     * @return [Context]
     */
    override fun fetchMainApplicationContext(): Context {
        return context
    }

    /**
     * To Hide Keyboard On Provided EditText
     */
    override fun hideKeyboard(editText: EditText) {
        editText.clearFocus()
        (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(
            editText.windowToken,
            0
        )
    }

    /**
     *  @return True If Build Is DEBUG Type As In Debug It's Debuggable.
     *  @return False If Build Is RELEASE Type As In Release It's Not Debuggable.
     */
    override fun isApplicationDebuggable(): Boolean {
        return enableLog
    }

    /**
     *  Detect If Application Is Running On Emulator
     *  @return True If Running On Emulator
     *  @return False If Not Running On Emulator
     */
    override fun isApplicationRunningOnEmulator(): Observable<Boolean> {
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

    /**
     *  Detect App Signature
     *  @return True If Genuine
     *  @return False If Non-Genuine
     *  @return False If Unable To Verify
     */
    @Suppress("PackageManagerGetSignatures", "DEPRECATION")
    override fun isApplicationSignatureValid(actualSignature: String): Observable<Boolean> {
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
                it.onNext(false)
                // Completing
                it.onComplete()
            }
        }
    }

    /**
     *  To Check If Auto-Update Time Is Enabled In Setting Of OS.
     *  @return True If Enabled
     *  @return False If Disabled
     */
    override fun isAutoUpdateOfTimeEnabled(): Observable<Boolean> {
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

    /**
     *  Detect Device Is Rooted Or Not With RootBeer & Google SafetyNet
     *  @return True If Device Is Rooted
     *  @return False if Device Isn't Rooted
     */
    override fun isDeviceRooted(): Observable<Boolean> {
        return Observable.create { isDeviceRooted ->
            try {
                val rootBeerResponse = RootBeer(context).isRootedWithoutBusyBoxCheck
                if (rootBeerResponse) {
                    // If Device Is Found To Be Rooted With RootBeer Library
                    isDeviceRooted.onNext(rootBeerResponse)
                } else {
                    // If Device Is Found Not Rooted With RootBeer Library Check With Google SafetyNet
                    isDeviceRooted.onNext(isDeviceRootedWithSafetyNet().blockingSingle())
                }
                // Completing
                isDeviceRooted.onComplete()
            } catch (error: Exception) {
                // An error occurred while verifying device integrity.
                showLog(TAG, "Error -> ${error.message}")
                isDeviceRooted.onError(error)
            }
        }
    }

    /**
     *  Detect Device Is Rooted Or Not With Google SafetyNet
     *  @return True If Device Is Rooted
     *  @return False if Device Isn't Rooted
     */
    override fun isDeviceRootedWithSafetyNet(): Observable<Boolean> {
        return Observable.create { isDeviceRooted ->
            try {
                if (GoogleApiAvailability
                        .getInstance()
                        .isGooglePlayServicesAvailable(context) == ConnectionResult.SUCCESS
                ) {
                    // The SafetyNet Attestation API is available.
                    showLog(TAG, "Sending SafetyNet API request.")
                    /*
                    Create a nonce for this request.
                    The nonce is returned as part of the response from the
                    SafetyNet API. Here we append the string to a number of random bytes to ensure it larger
                    than the minimum 16 bytes required.
                    Read out this value and verify it against the original request to ensure the
                    response is correct and genuine.
                    NOTE: A nonce must only be used once and a different nonce should be used for each request.
                    As a more secure option, you can obtain a nonce from your own server using a secure
                    connection. Here in this sample, we generate a String and append random bytes, which is not
                    very secure. Follow the tips on the Security Tips page for more information:
                    https://developer.android.com/training/articles/security-tips.html#Crypto
                     */
                    val nonceData = "Safety Net : " + System.currentTimeMillis()
                    val nonce = utilsDependencyProvided.getRequestNonce(nonceData)!!

                    SafetyNet.getClient(context).attest(nonce, SAFETY_NET_API_KEY)
                        .addOnSuccessListener { attestationResponse ->
                            /*
                             * Successfully communicated with SafetyNet API.
                             * Use result.getJwsResult() to get the signed result data. See the server
                             * component of this sample for details on how to verify and parse this result.
                             */
                            val mResult = attestationResponse.jwsResult
                            showLog(TAG, "Success! SafetyNet result:\n$mResult\n")
                            val response =
                                utilsDependencyProvided.parseJsonWebSignature(mResult)
                            showLog(
                                TAG,
                                "Success! SafetyNet Parsed result: ${gson.toJson(response)}"
                            )
                            // Emitting Response Of SafetyNet Negating Value As True Indicate Device Isn't Rooted.
                            isDeviceRooted.onNext(!response!!.basicIntegrity)
                            // Completing
                            isDeviceRooted.onComplete()
                        }
                        .addOnFailureListener { exception ->
                            // An error occurred while communicating with the service.
                            showLog(
                                TAG,
                                "Failed To Check With Google SafetyNet -> ${exception.message}"
                            )
                            // Emitting True As Unable To Verify Device Integrity
                            isDeviceRooted.onNext(true)
                            // Completing
                            isDeviceRooted.onComplete()

                        }
                } else {
                    // SafetyNet Attestation API isn't available.
                    showLog(TAG, "SafetyNet Attestation API isn't available.")
                    // Emitting True As Unable To Verify Device Integrity
                    isDeviceRooted.onNext(true)
                    // Completing
                    isDeviceRooted.onComplete()
                }
            } catch (error: Exception) {
                // Error Occurred While Verifying Device Integrity
                showLog(TAG, "Error Occurred While Verifying Device Integrity -> ${error.message}")
                // Emitting True As Unable To Verify Device Integrity Due To Error
                isDeviceRooted.onNext(true)
                // Completing
                isDeviceRooted.onComplete()
            }
        }
    }

    /**
     *  Detect If Application Is Installed Via PlayStore
     *  @return True If Installed Via PlayStore
     *  @return False If Installed Via Other Source
     */
    override fun isInstalledFromPlayStore(): Observable<Boolean> {
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
     *  To Check If Internet Is Available.
     *  @return True If Internet Is Available.
     *  @return False If Internet Isn't Available.
     */
    override fun isInternetAvailable(): Boolean {
        showLog(TAG, "isNetworkAvailable -> $isInternetAvailable")
        return isInternetAvailable
    }

    /**
     *  To Check If Supplied Email Is Valid
     *  @return True If Valid
     *  @return False If Invalid
     */
    override fun isValidEmail(email: String): Boolean {
        showLog(TAG, "isValidEmail($email)")
        return Patterns.EMAIL_ADDRESS.matcher(email)
            .matches()
    }

    /**
     *  Parse Date Provided In Millis Into Human Readable Form.
     *  @return Clear Text Readable By Human.
     */
    override fun parseDate(timeInMillis: Long): String {
        showLog(TAG, "Parsing -> $timeInMillis")
        val dateInText = dateFormatter.format(timeInMillis)
        showLog(TAG, "Parsed -> $dateInText")
        return dateInText
    }

    /**
     *  To Request User For Allowing To Read SMS
     */
    override fun requestSMSPermission(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray
    ) {
        if (smsVerifyCatcher != null) {
            try {
                showLog(TAG, "requestSMSPermission")
                smsVerifyCatcher!!.onRequestPermissionsResult(
                    requestCode,
                    permissions,
                    grantResults
                )
            } catch (exception: Exception) {
                showLog(TAG, "Exception requestSMSPermission -> ${exception.message}")
            }
        }
    }

    /**
     * To Show Keyboard On Provided [EditText].
     */
    override fun showKeyboard(editText: EditText) {
        editText.requestFocus()
        (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).showSoftInput(
            editText,
            InputMethodManager.SHOW_IMPLICIT
        )
        editText.setSelection(editText.text.toString().length)
    }

    /**
     * To Show Logs In Dalvik Debug Monitor Service.
     */
    override fun showLog(tag: String, message: String) {
        try {
            if (isApplicationDebuggable()) {
                Log.e(tag, message)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * To Show Toast In Application.
     */
    override fun showToast(message: String) {
        showLog(TAG, "showToast($context, $message)")
        try {
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * To Start Reading SMS For OTP Detection
     */
    override fun startReadingSMS(activity: Activity, contains: String) {
        showLog(TAG, "Start Reading Messages")
        SmsVerifyCatcher(activity, OnSmsCatchListener { message ->
            showLog(TAG, "SMS received: $message")
            when {
                message.contains(contains) -> {
                    showLog(TAG, "Message received : $message")
                    val otp = utilsDependencyProvided.extractSixDigitOTP(message).trim()
                    showLog(TAG, "Received OTP : $otp")
                    val otpArray = otp.toCharArray()
                    var isValidOTP = true
                    for (singleDigit in otpArray) {
                        try {
                            showLog(TAG, "OTP single digit : $singleDigit")
                            Integer.parseInt(singleDigit.toString())
                        } catch (e: Exception) {
                            isValidOTP = false
                            showLog(TAG, "Exception in OTP ${e.message}")
                        }
                    }
                    if (isValidOTP) {
                        TejoraBus.publish(SMSReceived(message, otp))
                    }
                }
                else -> {
                    showLog(TAG, "Invalid OTP")
                }
            }
        }).apply {
            smsVerifyCatcher = this
            this.onStart()
        }
    }

    /**
     * To Stop Reading SMS For OTP Detection
     */
    override fun stopReadingSMS() {
        showLog(TAG, "Stop Reading Messages")
        if (smsVerifyCatcher != null) {
            smsVerifyCatcher.apply {
                this!!.onStop()
                smsVerifyCatcher = null
            }
        }
    }

    /**
     *  Unzip  Zipped File.
     *  Return Text Content Of The File In String Format.
     *  @return [String] Extracted Of Zipped Text File.
     */
    override fun unzip(zipFileName: String): Observable<String> {
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

    /**
     * Common [String] Keys Used In This Class.
     */
    companion object {
        private const val TAG = "IUtils"
        private const val DEFAULT_DATE_FORMAT = "yyyy MMM dd"
        private const val LOGOUT_CONSENT = "LOGOUT"
        private const val GOOGLE_PLAY_STORE_INSTALLER = "com.android.vending"
        private const val SAFETY_NET_API_KEY = "AIzaSyA6TQiStAhHjd-0GqJnjjkEGKS-7DCyxFI"
    }
}