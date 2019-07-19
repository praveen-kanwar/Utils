package com.tejora.utils

import android.content.Context
import android.net.ConnectivityManager
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
            if (getBuildType()) {
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
            Toast.makeText(context, message, Toast.LENGTH_SHORT)
                .show()
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
        pageName: String = "Page From Dialog Is Displayed",
        reasonForDisplay: String = "Reason To Display Dialog.",
        title: String = "Dialog Title",
        message: String = "Message To Be Displayed..",
        cancelMessage: String = "Cancel",
        okayMessage: String = "Okay"
    ) {
        try {
            val response = TejoraDialogResponse(pageName, reasonForDisplay, title, message, cancelMessage, okayMessage)
            context.let { context ->
                AlertDialog.Builder(context)
                    .setMessage(message)
                    .setPositiveButton(okayMessage) { dialog, _ ->
                        response.userOpted = okayMessage
                        TejoraBus.publish(response)
                        dialog.dismiss()
                    }
                    .setNegativeButton(cancelMessage) { dialog, _ ->
                        response.userOpted = cancelMessage
                        TejoraBus.publish(response)
                        dialog.dismiss()
                    }
                    .create()
                    .show()
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
    private fun getBuildType(): Boolean {
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

    companion object {
        const val DEBUG = "DEBUG"
        const val RELEASE = "RELEASE"
    }
}