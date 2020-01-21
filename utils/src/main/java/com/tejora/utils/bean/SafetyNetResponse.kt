package com.tejora.utils.bean

import com.google.gson.annotations.SerializedName

data class SafetyNetResponse(
    @SerializedName("nonce")
    val nonce: String,
    @SerializedName("timestampMs")
    val timestampMs: Long,
    @SerializedName("apkPackageName")
    val apkPackageName: String,
    @SerializedName("apkDigestSha256")
    val apkDigestSha256: String,
    @SerializedName("ctsProfileMatch")
    val ctsProfileMatch: Boolean,
    @SerializedName("apkCertificateDigestSha256")
    val apkCertificateDigestSha256: List<String>,
    @SerializedName("basicIntegrity")
    val basicIntegrity: Boolean
)