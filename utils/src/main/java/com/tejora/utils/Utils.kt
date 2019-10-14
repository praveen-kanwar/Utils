@file:Suppress("DEPRECATION")

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
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telephony.TelephonyManager
import android.text.TextUtils
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
import java.math.BigInteger
import java.security.*
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton
import javax.security.auth.x500.X500Principal
import kotlin.math.abs

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
            ) == PackageManager.PERMISSION_GRANTED
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
            ) == PackageManager.PERMISSION_GRANTED
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

    fun encrypt(plainText: String): String {
        showLog(TAG, "Encrypting $plainText")
        try {
            val publicKey = getSecuredUserPrivateKeyEntry()!!.certificate.publicKey
            val cipher = getCipher()
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            return Base64.encodeToString(cipher.doFinal(plainText.toByteArray()), Base64.NO_WRAP)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }

    }

    fun decrypt(cipherText: String): String {
        showLog(TAG, "Decrypting $cipherText")
        try {
            val privateKey = getSecuredUserPrivateKeyEntry()!!.privateKey
            val cipher = getCipher()
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return String(cipher.doFinal(Base64.decode(cipherText, Base64.NO_WRAP)))
        } catch (e: Exception) {
            throw RuntimeException(e)
        }

    }

    private fun getSecuredUserPrivateKeyEntry(): KeyStore.PrivateKeyEntry? {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)
            val entry = keyStore.getEntry(ANDROID_KEYSTORE_ALIAS, null)
            if (entry == null) {
                showLog(TAG, "No Key Found Under Alias -> $ANDROID_KEYSTORE_ALIAS")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    createKeysMarshmallow()
                } else {
                    createKeysPreMarshmallow(context)
                }
                return keyStore.getEntry(ANDROID_KEYSTORE_ALIAS, null) as KeyStore.PrivateKeyEntry?
            }
            if (entry !is KeyStore.PrivateKeyEntry) {
                showLog(TAG, "Not An Instance Of A PrivateKeyEntry")
                return null
            }
            return entry
        } catch (e: Exception) {
            showLog(TAG, e.message!!)
            return null
        }

    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class)
    private fun getCipher(): Cipher {
        return Cipher.getInstance(
            String.format(
                "%s/%s/%s",
                TYPE_RSA,
                BLOCKING_MODE,
                PADDING_TYPE
            )
        )
    }

    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    @Throws(
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class,
        InvalidAlgorithmParameterException::class
    )
    private fun createKeysPreMarshmallow(context: Context) {
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 30)
        val spec = KeyPairGeneratorSpec.Builder(context)
            .setAlias(ANDROID_KEYSTORE_ALIAS)
            .setSubject(X500Principal("CN=${ANDROID_KEYSTORE_ALIAS}"))
            .setSerialNumber(BigInteger.valueOf(abs(ANDROID_KEYSTORE_ALIAS.hashCode()).toLong()))
            // Date range of validity for the generated pair.
            .setStartDate(start.time).setEndDate(end.time)
            .build()

        val userSessionKeyPairGenerator = KeyPairGenerator.getInstance(
            TYPE_RSA,
            ANDROID_KEYSTORE_PROVIDER
        )
        userSessionKeyPairGenerator.initialize(spec)
        val userSessionKeyPair = userSessionKeyPairGenerator.generateKeyPair()
        showLog(TAG, "User Session Public Key is: " + userSessionKeyPair.public.toString())
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun createKeysMarshmallow() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(
                KeyGenParameterSpec.Builder(
                    ANDROID_KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(
                            1024,
                            RSAKeyGenParameterSpec.F4
                        )
                    )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512
                    )
                    .setUserAuthenticationRequired(false)
                    .build()
            )
            val userSessionKeyPair = keyPairGenerator.generateKeyPair()
            showLog(
                TAG,
                "User Session Public Key is: " + userSessionKeyPair.public.toString()
            )
        } catch (e: NoSuchProviderException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }
    }

    fun encryptClearText(clearText: String): String {
        showLog(TAG, "Encrypt Clear Text -> $clearText")
        val clearTextByteArray = clearText.toByteArray(Charsets.UTF_8)
        showLog(TAG, "Encrypt Clear Text ByteArray -> ${clearTextByteArray.contentToString()}")
        val clearTextEncodedByteArray = Base64.encode(clearTextByteArray, Base64.DEFAULT)
        showLog(
            TAG,
            "Encrypt Clear Text Encoded ByteArray -> ${clearTextEncodedByteArray!!.contentToString()}"
        )
        val cipherTextByteArray = getClearTextEncryptionCipher().doFinal(clearTextEncodedByteArray)
        showLog(
            TAG,
            "Encrypted Cipher Text ByteArray -> ${cipherTextByteArray!!.contentToString()}"
        )
        val cipherTextString = Base64.encodeToString(cipherTextByteArray, Base64.DEFAULT)
        showLog(TAG, "Encrypted Cipher Text -> $cipherTextString")
        return cipherTextString
    }

    fun decryptCipherText(cipherText: String): String {
        showLog(TAG, "Decrypt Cipher Text -> $cipherText")
        val cipherTextByteArray = Base64.decode(cipherText, Base64.DEFAULT)
        showLog(TAG, "Decrypt Cipher Text ByteArray -> ${cipherTextByteArray!!.contentToString()}")
        val clearTextEncodedByteArray = getCipherTextDecryptionCipher().doFinal(cipherTextByteArray)
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

    private fun getClearTextEncryptionCipher(): Cipher {
        val cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            getSecretKeySpec(),
            IvParameterSpec(getInitializationVector())
        )
        return cipher
    }

    private fun getCipherTextDecryptionCipher(): Cipher {
        val cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getSecretKeySpec(),
            IvParameterSpec(getInitializationVector())
        )
        return cipher
    }

    private fun getSecretKeyFactory(): SecretKeyFactory {
        return SecretKeyFactory.getInstance(ENCRYPTION_ALGORITHM_SECRET_KEY_FACTORY)
    }

    private fun getPBEKeySpec(): PBEKeySpec {
        return PBEKeySpec(
            ENCRYPTION_KEY.toCharArray(),
            getSalt(),
            ENCRYPTION_ITERATION_COUNT,
            ENCRYPTION_KEY_LENGTH
        )
    }

    private fun getSecretKeySpec(): SecretKeySpec {
        return SecretKeySpec(
            getSecretKeyFactory().generateSecret(getPBEKeySpec()).encoded,
            ENCRYPTION_ALGORITHM_SECRET_KEY_SPEC
        )
    }

    private fun getSalt(): ByteArray {
        val saltString = context.getSharedPreferences(TAG, Context.MODE_PRIVATE)
            .getString(ENCRYPTION_SALT_KEY, null)
        showLog(TAG, "Retrieved Salt String -> $saltString")
        return if (TextUtils.isEmpty(saltString)) {
            saveSalt(generateSalt())
        } else {
            val salt = Base64.decode(saltString!!, Base64.DEFAULT)
            showLog(TAG, "Retrieved Salt -> ${salt!!.contentToString()}")
            salt
        }
    }

    private fun saveSalt(saltByteArray: ByteArray): ByteArray {
        val editor = context.getSharedPreferences(TAG, Context.MODE_PRIVATE).edit()
        showLog(TAG, "Saving Salt -> ${saltByteArray.contentToString()}")
        val saltString = Base64.encodeToString(saltByteArray, Base64.DEFAULT)
        showLog(TAG, "Saving Salt String -> $saltString")
        editor.putString(ENCRYPTION_SALT_KEY, saltString)
        editor.apply()
        return saltByteArray
    }

    private fun generateSalt(): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(ENCRYPTION_SALT_KEY_LENGTH)
        random.nextBytes(salt)
        showLog(TAG, "Generated Salt -> ${salt.contentToString()}")
        return salt
    }

    private fun getInitializationVector(): ByteArray {
        val initializationVectorString =
            context.getSharedPreferences(TAG, Context.MODE_PRIVATE)
                .getString(ENCRYPTION_INITIALIZATION_VECTOR_KEY, null)
        showLog(TAG, "Retrieved IV String -> $initializationVectorString")
        return if (TextUtils.isEmpty(initializationVectorString)) {
            saveInitializationVector(generateInitializationVector())
        } else {
            val initializationVector = Base64.decode(initializationVectorString!!, Base64.DEFAULT)
            showLog(TAG, "Retrieved IV -> ${initializationVector!!.contentToString()}")
            initializationVector
        }
    }

    private fun saveInitializationVector(initializationVectorByteArray: ByteArray): ByteArray {
        val editor = context.getSharedPreferences(TAG, Context.MODE_PRIVATE).edit()
        showLog(TAG, "Saving IV -> ${initializationVectorByteArray.contentToString()}")
        val ivString = Base64.encodeToString(initializationVectorByteArray, Base64.DEFAULT)
        showLog(TAG, "Saving IV String -> $ivString")
        editor.putString(ENCRYPTION_INITIALIZATION_VECTOR_KEY, ivString)
        editor.apply()
        return initializationVectorByteArray
    }

    private fun generateInitializationVector(): ByteArray {
        val random = SecureRandom()
        val initializationVector = ByteArray(ENCRYPTION_INITIALIZATION_VECTOR_KEY_LENGTH)
        random.nextBytes(initializationVector)
        showLog(TAG, "Generated IV -> ${initializationVector.contentToString()}")
        return initializationVector
    }

    @Suppress("unused")
    companion object {
        const val TAG = "Utils"
        const val DEBUG = "DEBUG"
        const val RELEASE = "RELEASE"
        const val GOOGLE_PLAY_STORE_INSTALLER = "com.android.vending"
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val ANDROID_KEYSTORE_ALIAS = "PrAVeEnKaNwAr"
        private const val TYPE_RSA = "RSA"
        private const val PADDING_TYPE = "PKCS1Padding"
        private const val BLOCKING_MODE = "NONE"
        private const val ENCRYPTION_TRANSFORMATION = "AES/CBC/PKCS7Padding"
        private const val ENCRYPTION_ALGORITHM_SECRET_KEY_FACTORY = "PBKDF2WithHmacSHA1"
        private const val ENCRYPTION_ALGORITHM_SECRET_KEY_SPEC = "AES"
        private const val ENCRYPTION_KEY_LENGTH = 256
        private const val ENCRYPTION_KEY = "KaNwArPrAVeEn"
        private const val ENCRYPTION_ITERATION_COUNT = 9833
        private const val ENCRYPTION_SALT_KEY_LENGTH = 256
        private const val ENCRYPTION_SALT_KEY = "ENCRYPTION_SALT"
        private const val ENCRYPTION_INITIALIZATION_VECTOR_KEY_LENGTH = 16
        private const val ENCRYPTION_INITIALIZATION_VECTOR_KEY = "ENCRYPTION_INITIALIZATION_VECTOR"
    }
}