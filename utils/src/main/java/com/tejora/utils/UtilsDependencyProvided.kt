@file:Suppress("DEPRECATION")

package com.tejora.utils

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telephony.TelephonyManager
import android.text.TextUtils
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import com.google.gson.Gson
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import java.util.regex.Pattern
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

@Singleton
class UtilsDependencyProvided
@Inject
constructor(private val context: Context, private val gson: Gson) {

    /**
     * Create Key In KeyStore For OS [Build.VERSION_CODES.M] & Above.
     */
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
            keyPairGenerator.generateKeyPair()
        } catch (e: NoSuchProviderException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }
    }

    /**
     * Create Key In KeyStore For OS [Build.VERSION_CODES.LOLLIPOP] & [Build.VERSION_CODES.LOLLIPOP_MR1].
     */
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
        userSessionKeyPairGenerator.generateKeyPair()
    }

    /**
     * Decrypt Database Key.
     * @return [String] Clear Text Of Database Key.
     */
    private fun decryptDatabaseKey(cipherText: String): String {
        try {
            val privateKey = getSecuredUserPrivateKeyEntry()!!.privateKey
            val cipher = getDatabaseKeyCipher()
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return String(cipher.doFinal(Base64.decode(cipherText, Base64.NO_WRAP)))
        } catch (e: Exception) {
            throw RuntimeException(e)
        }

    }

    /**
     * Encrypt Database Key.
     * @return [Cipher] [String] Of Database Key.
     */
    private fun encryptDatabaseKey(plainText: String): String {
        try {
            val publicKey = getSecuredUserPrivateKeyEntry()!!.certificate.publicKey
            val cipher = getDatabaseKeyCipher()
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            return Base64.encodeToString(cipher.doFinal(plainText.toByteArray()), Base64.NO_WRAP)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }

    }

    /**
     * Extract Four Digit OTP From Given String
     * @return OTP Of Six Digit Extracted From Input [String] Of SMS.
     */
    fun extractFourDigitOTP(sms: String): String {
        val otpPattern = Pattern.compile("\\d{4}")
        val otpMatcher = otpPattern.matcher(sms)
        return if (otpMatcher.find()) {
            ((otpMatcher.group(0)) ?: "")
        } else ""
    }

    /**
     * Extract Six Digit OTP From Given String
     * @return OTP Of Six Digit Extracted From Input [String] Of SMS.
     */
    fun extractSixDigitOTP(sms: String): String {
        val otpPattern = Pattern.compile("\\d{6}")
        val otpMatcher = otpPattern.matcher(sms)
        return if (otpMatcher.find()) {
            ((otpMatcher.group(0)) ?: "")
        } else ""
    }

    /**
     * Fetch Database Key, Which Is Responsible For Encryption Of Database.
     * @return [ByteArray] Of Database Encryption Key.
     */
    fun fetchDatabaseEncryptionKey(): ByteArray {
        // Fetch Encrypted Database Encryption Key From SharedPreference
        val databaseEncryptionKey =
            context.getSharedPreferences(TAG, Context.MODE_PRIVATE)
                .getString(DATABASE_ENCRYPTION_KEY, null)
        return if (TextUtils.isEmpty(databaseEncryptionKey)) {
            // If Null Generate A Random Key, Save It And Then Return
            generateDatabaseEncryptionKey()
        } else {
            // Decrypt Encrypted Database Key Retrieved From SharedPreference & Return
            Base64.decode(decryptDatabaseKey(databaseEncryptionKey!!), Base64.DEFAULT)
        }
    }

    /**
     * Create/Generate A Random Key Responsible For Encryption Of Database.
     * @return [ByteArray] Of Generated Database Encryption Key.
     */
    private fun generateDatabaseEncryptionKey(): ByteArray {
        // Create Empty ByteArray Of Key Size
        val databaseEncryptionKey = ByteArray(64)
        // Random Number Generator
        val secureRandom = SecureRandom()
        // Initialize Empty ByteArray Of Key
        secureRandom.nextBytes(databaseEncryptionKey)
        // Save Generated Key For Database Encryption
        saveDatabaseEncryptionKey(databaseEncryptionKey)
        // Return Generated Key For Database Encryption
        return databaseEncryptionKey
    }

    /**
     * Create/Generate A Random Initialization Vector Responsible For Encryption Of Clear Text.
     * @return [ByteArray] Of Generated Initialization Vector.
     */
    private fun generateInitializationVector(): ByteArray {
        val random = SecureRandom()
        val initializationVector = ByteArray(ENCRYPTION_INITIALIZATION_VECTOR_KEY_LENGTH)
        random.nextBytes(initializationVector)
        return initializationVector
    }

    /**
     * Create/Generate A Random Salt Responsible For Encryption Of Clear Text.
     * @return [ByteArray] Of Generated Salt
     */
    private fun generateSalt(): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(ENCRYPTION_SALT_KEY_LENGTH)
        random.nextBytes(salt)
        return salt
    }

    /**
     * Get Cipher For Decryption Of Cipher Text & Convert To Clear Text.
     * @return [Cipher] Of [Cipher.DECRYPT_MODE] To Decrypt [Cipher] Text To Clear Text.
     */
    fun getCipherTextDecryptionCipher(): Cipher {
        val cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getSecretKeySpec(),
            IvParameterSpec(getInitializationVector())
        )
        return cipher
    }

    /**
     * Get Cipher For Encryption Of Clear Text & Convert To Cipher Text.
     * @return [Cipher] Of [Cipher.ENCRYPT_MODE] To Encrypt Clear Text To [Cipher] Text.
     */
    fun getClearTextEncryptionCipher(): Cipher {
        val cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            getSecretKeySpec(),
            IvParameterSpec(getInitializationVector())
        )
        return cipher
    }

    /**
     * Get Cipher For Encryption Of Database Key.
     * @return [Cipher] To Encrypt/Decrypt Database Key.
     */
    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class)
    private fun getDatabaseKeyCipher(): Cipher {
        return Cipher.getInstance(
            String.format(
                "%s/%s/%s",
                TYPE_RSA,
                BLOCKING_MODE,
                PADDING_TYPE
            )
        )
    }

    /**
     * This Method Will Return Device International Mobile Equipment Identity.
     * @return IMEI Of Mobile In [String] Format For OS [Build.VERSION_CODES.O] & Above.
     */
    @SuppressLint("HardwareIds")
    @RequiresApi(Build.VERSION_CODES.O)
    fun getDeviceIMEIPostOreo(telephonyManager: TelephonyManager): String {
        return if (ActivityCompat.checkSelfPermission(
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
    }

    /**
     * This Method Will Return Device International Mobile Equipment Identity.
     * @return IMEI Of Mobile In [String] Format For OS [Build.VERSION_CODES.LOLLIPOP] Till [Build.VERSION_CODES.N_MR1].
     */
    @Suppress("HardwareIds")
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun getDeviceIMEIPreOreo(telephonyManager: TelephonyManager): String {
        return if (ActivityCompat.checkSelfPermission(
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
    }

    /**
     * Fetch Initialization Vector Responsible For Encryption Of Clear Text.
     * @return [ByteArray] Of Initialization Vector.
     */
    private fun getInitializationVector(): ByteArray {
        val initializationVectorString =
            context.getSharedPreferences(TAG, Context.MODE_PRIVATE)
                .getString(ENCRYPTION_INITIALIZATION_VECTOR_KEY, null)
        return if (TextUtils.isEmpty(initializationVectorString)) {
            saveInitializationVector(generateInitializationVector())
        } else {
            val initializationVector = Base64.decode(initializationVectorString!!, Base64.DEFAULT)
            initializationVector
        }
    }

    /**
     * Generates a 16-byte nonce with additional data.
     * The nonce should also include additional information, such as a user id or any other details
     * you wish to bind to this attestation. Here you can provide a String that is included in the
     * nonce after 24 random bytes. During verification, extract this data again and check it
     * against the request that was made with this nonce.
     */
    fun getRequestNonce(data: String): ByteArray? {
        val byteStream = ByteArrayOutputStream()
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        try {
            byteStream.write(bytes)
            byteStream.write(data.toByteArray())
        } catch (e: IOException) {
            return null
        }
        return byteStream.toByteArray()
    }

    /**
     * Get Password Based Encryption Key Provider.
     * @return [PBEKeySpec] Which Is Required For Encryption Of Clear Text.
     */
    private fun getPBEKeySpec(): PBEKeySpec {
        return PBEKeySpec(
            ENCRYPTION_KEY.toCharArray(),
            getSalt(),
            ENCRYPTION_ITERATION_COUNT,
            ENCRYPTION_KEY_LENGTH
        )
    }

    /**
     * Fetch Salt Responsible For Encryption Of Clear Text.
     * @return [ByteArray] Of Salt.
     */
    private fun getSalt(): ByteArray {
        val saltString = context.getSharedPreferences(TAG, Context.MODE_PRIVATE)
            .getString(ENCRYPTION_SALT_KEY, null)
        return if (TextUtils.isEmpty(saltString)) {
            saveSalt(generateSalt())
        } else {
            val salt = Base64.decode(saltString!!, Base64.DEFAULT)
            salt
        }
    }

    /**
     * Get Secret Key Factory.
     * @return [SecretKeyFactory] Which Is Required For Defining Algorithm Of Encryption Of Clear Text.
     */
    private fun getSecretKeyFactory(): SecretKeyFactory {
        return SecretKeyFactory.getInstance(ENCRYPTION_ALGORITHM_SECRET_KEY_FACTORY)
    }

    /**
     * Get Secret Key Factory, Provider Of Secret Key.
     * @return [SecretKeySpec] Which Is Required For Defining Algorithm Of Encryption Of Clear Text.
     */
    private fun getSecretKeySpec(): SecretKeySpec {
        return SecretKeySpec(
            getSecretKeyFactory().generateSecret(getPBEKeySpec()).encoded,
            ENCRYPTION_ALGORITHM_SECRET_KEY_SPEC
        )
    }

    /**
     * Get Secured User Private Key, Stored In KeyStore For Encryption/Decryption Of Database Key.
     * @return [KeyStore.PrivateKeyEntry] Which Is Required For Encryption/Decryption Of Database Key.
     */
    private fun getSecuredUserPrivateKeyEntry(): KeyStore.PrivateKeyEntry? {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            keyStore.load(null)
            val entry = keyStore.getEntry(ANDROID_KEYSTORE_ALIAS, null)
            if (entry == null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    createKeysMarshmallow()
                } else {
                    createKeysPreMarshmallow(context)
                }
                return keyStore.getEntry(ANDROID_KEYSTORE_ALIAS, null) as KeyStore.PrivateKeyEntry?
            }
            if (entry !is KeyStore.PrivateKeyEntry) {
                return null
            }
            return entry
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Parse SafetyNet Response
     * Can Be Retrieved Later via [fetchDatabaseEncryptionKey]
     */
    fun parseJsonWebSignature(jwsResult: String?): String {
        val jwtParts = jwsResult?.split("\\.".toRegex())?.dropLastWhile { it.isEmpty() }
        return jwtParts?.takeIf { it.size >= 2 }?.let {
            // We're only interested in the body/payload
            String(Base64.decode(it[1], Base64.DEFAULT))
        }.toString()
    }

    /**
     * Save Database Encryption Key.
     * Can Be Retrieved Later via [fetchDatabaseEncryptionKey]
     */
    private fun saveDatabaseEncryptionKey(databaseEncryptionKey: ByteArray) {
        val editor = context.getSharedPreferences(TAG, Context.MODE_PRIVATE).edit()
        editor.putString(
            DATABASE_ENCRYPTION_KEY,
            encryptDatabaseKey(Base64.encodeToString(databaseEncryptionKey, Base64.DEFAULT))
        )
        editor.apply()
    }

    /**
     * Save Initialization Vector, Used For Encryption/Decryption Of Clear/Cipher Text.
     * Can Be Retrieved Later via [getInitializationVector]
     */
    private fun saveInitializationVector(initializationVectorByteArray: ByteArray): ByteArray {
        val editor = context.getSharedPreferences(TAG, Context.MODE_PRIVATE).edit()
        val ivString = Base64.encodeToString(initializationVectorByteArray, Base64.DEFAULT)
        editor.putString(ENCRYPTION_INITIALIZATION_VECTOR_KEY, ivString)
        editor.apply()
        return initializationVectorByteArray
    }

    /**
     * Save Salt, Used For Encryption/Decryption Of Clear/Cipher Text.
     * Can Be Retrieved Later via [getSalt]
     */
    private fun saveSalt(saltByteArray: ByteArray): ByteArray {
        val editor = context.getSharedPreferences(TAG, Context.MODE_PRIVATE).edit()
        val saltString = Base64.encodeToString(saltByteArray, Base64.DEFAULT)
        editor.putString(ENCRYPTION_SALT_KEY, saltString)
        editor.apply()
        return saltByteArray
    }

    /**
     * Common [String] Keys Used In This Class.
     */
    companion object {
        const val TAG = "UtilsDependencyProvided"
        private const val DATABASE_ENCRYPTION_KEY = "DATABASE_ENCRYPTION_KEY"
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