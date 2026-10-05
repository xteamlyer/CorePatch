package org.lsposed.corepatch.hook

import org.lsposed.corepatch.XposedHelper
import org.lsposed.corepatch.XposedHelper.hostClassLoader
import java.lang.reflect.Method

object GlobalCryptoHook : BaseHook() {
    override val name = "GlobalCryptoHook"

    override fun hook() {
        val signatureClass = hostClassLoader.loadClass("java.security.Signature")

        val verifyByteArray = signatureClass.getDeclaredMethod(
            "verify",
            ByteArray::class.java
        )

        val verifyByteArrayRange = signatureClass.getDeclaredMethod(
            "verify",
            ByteArray::class.java,
            Int::class.javaPrimitiveType!!,
            Int::class.javaPrimitiveType!!
        )

        hookReturnTrue(verifyByteArray)
        hookReturnTrue(verifyByteArrayRange)

        val messageDigestClass =
            hostClassLoader.loadClass("java.security.MessageDigest")

        val isEqual = messageDigestClass.getDeclaredMethod(
            "isEqual",
            ByteArray::class.java,
            ByteArray::class.java
        )

        hookReturnTrue(isEqual)
    }

    private fun hookReturnTrue(method: Method) {
        XposedHelper.deoptimize(method)
        XposedHelper.hookBefore(method) { callback ->
            callback.returnAndSkip(true)
        }
    }
}