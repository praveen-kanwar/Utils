package com.tejora.utils

data class TejoraDialogResponse(
    val pageName: String = "Page From Dialog Is Displayed", // From Which Fragment Or Activity It's Called.
    val reasonForDisplay: String = "Reason To Display Dialog.", // Why It's Displayed On Application.
    val title: String? = "Dialog Title", // Title Of Dialog.
    val message: String = "Message To Be Displayed..", // Message To Be Displayed To User
    val cancelMessage: String? = "Cancel", // Cancel Button Text
    val okayMessage: String = "Okay", // Okay Button Text
    var userOpted: String = "Cancel" // User Clicked On Cancel Or Okay.
)