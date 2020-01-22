package com.tejora.utils

import android.app.Activity
import android.content.Context
import android.widget.EditText
import io.reactivex.Observable

/**
 * Context Should Be Of Application For Correct & Optimal Performance
 */
interface Utils {

    /**
     *  Decrypt Supplied Cipher Text.
     *  @return Clear Text Readable By Human.
     */
    fun decryptCipherText(cipherText: String): String

    /**
     * To Enable/Disable Logs In Dalvik Debug Monitor Service.
     */
    fun enableLog(enableLog: Boolean)

    /**
     *  Encrypt Supplied Clear Text.
     *  @return Cipher Text Not Readable By Human.
     */
    fun encryptClearText(clearText: String): String

    /**
     *  To Fetch Unique Database Key, Responsible For Database Encryption.
     *  @return ByteArray To Encrypt Database.
     */
    fun fetchDatabaseEncryptionKey(): ByteArray

    /**
     * To Fetch Device International Mobile Equipment Identity (IMEI).
     * @return IMEI Of Device
     */
    fun fetchDeviceIMEI(): String

    /**
     * To Fetch Context Of Application
     * @return [Context]
     */
    fun fetchMainApplicationContext(): Context

    /**
     * To Hide Keyboard On Provided EditText
     */
    fun hideKeyboard(editText: EditText)

    /**
     *  @return True If Build Is DEBUG Type As In Debug It's Debuggable.
     *  @return False If Build Is RELEASE Type As In Release It's Not Debuggable.
     */
    fun isApplicationDebuggable(): Boolean

    /**
     *  Detect If Application Is Running On Emulator
     *  @return True If Running On Emulator
     *  @return False If Not Running On Emulator
     */
    fun isApplicationRunningOnEmulator(): Observable<Boolean>

    /**
     *  Detect App Signature
     *  @return True If Genuine
     *  @return False If Non-Genuine
     *  @return False If Unable To Verify
     */
    fun isApplicationSignatureValid(actualSignature: String): Observable<Boolean>

    /**
     *  To Check If Auto-Update Time Is Enabled In Setting Of OS.
     *  @return True If Enabled
     *  @return False If Disabled
     */
    fun isAutoUpdateOfTimeEnabled(): Observable<Boolean>

    /**
     *  Detect Device Is Rooted Or Not
     *  @return True If Device Is Rooted
     *  @return False if Device Isn't Rooted
     */
    fun isDeviceRooted(): Observable<Boolean>

    /**
     *  Detect Device Is Rooted Or Not With Google SafetyNet
     *  @return True If Device Is Rooted
     *  @return False if Device Isn't Rooted
     */
    fun isDeviceRootedWithSafetyNet(): Observable<Boolean>

    /**
     *  Detect If Application Is Installed Via PlayStore
     *  @return True If Installed Via PlayStore
     *  @return False If Installed Via Other Source
     */
    fun isInstalledFromPlayStore(): Observable<Boolean>

    /**
     *  To Check If Internet Is Available.
     *  @return True If Internet Is Available.
     *  @return False If Internet Isn't Available.
     */
    fun isInternetAvailable(): Boolean

    /**
     *  To Check If Supplied Email Is Valid
     *  @return True If Valid
     *  @return False If Invalid
     */
    fun isValidEmail(email: String): Boolean

    /**
     * Parse Date Provided In Millis Into Human Readable Form
     * @return Human Readable Date
     */
    fun parseDate(timeInMillis: Long): String

    /**
     *  To Request User For Allowing To Read SMS
     */
    fun requestSMSPermission(requestCode: Int, permissions: Array<String>, grantResults: IntArray)

    /**
     * To Show Keyboard On Provided EditText
     */
    fun showKeyboard(editText: EditText)

    /**
     * To Show Logs In Dalvik Debug Monitor Service.
     */
    fun showLog(tag: String, message: String)

    /**
     * To Show Toast In Application
     */
    fun showToast(message: String)

    /**
     * To Start Reading SMS For OTP Detection
     */
    fun startReadingSMS(activity: Activity, contains: String)

    /**
     * To Stop Reading SMS For OTP Detection
     */
    fun stopReadingSMS()

    /**
     *  Unzip  Zipped File.
     *  Return Text Content Of The File In String Format
     *  @return String Extracted Of Zipped Text File
     */
    fun unzip(zipFileName: String): Observable<String>
}