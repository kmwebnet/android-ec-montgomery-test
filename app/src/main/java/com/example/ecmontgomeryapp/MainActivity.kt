package com.example.ecmontgomeryapp

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class MainActivity : AppCompatActivity() {
    private val _tag = "KeyStoreProviderSample"
    private var rfc7748X25519PrivateKey: PrivateKey? = null
    private var rfc7748X25519PublicKey: PublicKey? = null

    private val _alicesPrivKey = byteArrayOf(
        0x30.toByte(),
        0x2e.toByte(),
        0x02.toByte(),
        0x01.toByte(),
        0x00.toByte(),
        0x30.toByte(),
        0x05.toByte(),
        0x06.toByte(),
        0x03.toByte(),
        0x2b.toByte(),
        0x65.toByte(),
        0x6e.toByte(),
        0x04.toByte(),
        0x22.toByte(),
        0x04.toByte(),
        0x20.toByte(), //end PKCS header
        0x77.toByte(),
        0x07.toByte(),
        0x6d.toByte(),
        0x0a.toByte(),
        0x73.toByte(),
        0x18.toByte(),
        0xa5.toByte(),
        0x7d.toByte(),
        0x3c.toByte(),
        0x16.toByte(),
        0xc1.toByte(),
        0x72.toByte(),
        0x51.toByte(),
        0xb2.toByte(),
        0x66.toByte(),
        0x45.toByte(),
        0xdf.toByte(),
        0x4c.toByte(),
        0x2f.toByte(),
        0x87.toByte(),
        0xeb.toByte(),
        0xc0.toByte(),
        0x99.toByte(),
        0x2a.toByte(),
        0xb1.toByte(),
        0x77.toByte(),
        0xfb.toByte(),
        0xa5.toByte(),
        0x1d.toByte(),
        0xb9.toByte(),
        0x2c.toByte(),
        0x2a.toByte()

    )

    private val _bobsPubKey = byteArrayOf(
        0x30.toByte(),
        0x2a.toByte(),
        0x30.toByte(),
        0x05.toByte(),
        0x06.toByte(),
        0x03.toByte(),
        0x2b.toByte(),
        0x65.toByte(),
        0x6e.toByte(),
        0x03.toByte(),
        0x21.toByte(),
        0x00.toByte(), // end x509 header
        0xde.toByte(),
        0x9e.toByte(),
        0xdb.toByte(),
        0x7d.toByte(),
        0x7b.toByte(),
        0x7d.toByte(),
        0xc1.toByte(),
        0xb4.toByte(),
        0xd3.toByte(),
        0x5b.toByte(),
        0x61.toByte(),
        0xc2.toByte(),
        0xec.toByte(),
        0xe4.toByte(),
        0x35.toByte(),
        0x37.toByte(),
        0x3f.toByte(),
        0x83.toByte(),
        0x43.toByte(),
        0xc8.toByte(),
        0x5b.toByte(),
        0x78.toByte(),
        0x67.toByte(),
        0x4d.toByte(),
        0xad.toByte(),
        0xfc.toByte(),
        0x7e.toByte(),
        0x14.toByte(),
        0x6f.toByte(),
        0x88.toByte(),
        0x2b.toByte(),
        0x4f.toByte()

    )

    private val _expectedSecret = byteArrayOf(
        0x4a.toByte(),
        0x5d.toByte(),
        0x9d.toByte(),
        0x5b.toByte(),
        0xa4.toByte(),
        0xce.toByte(),
        0x2d.toByte(),
        0xe1.toByte(),
        0x72.toByte(),
        0x8e.toByte(),
        0x3b.toByte(),
        0xf4.toByte(),
        0x80.toByte(),
        0x35.toByte(),
        0x0f.toByte(),
        0x25.toByte(),
        0xe0.toByte(),
        0x7e.toByte(),
        0x21.toByte(),
        0xc9.toByte(),
        0x47.toByte(),
        0xd1.toByte(),
        0x9e.toByte(),
        0x33.toByte(),
        0x76.toByte(),
        0xf0.toByte(),
        0x9b.toByte(),
        0x3c.toByte(),
        0x1e.toByte(),
        0x16.toByte(),
        0x17.toByte(),
        0x42.toByte()

    )

    private fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val button = findViewById<View>(R.id.button) as Button
        button.setOnClickListener {
            var view: TextView = findViewById<View>(R.id.textView) as TextView
            view.text = _alicesPrivKey.toHex()

            view = findViewById<View>(R.id.textView4) as TextView
            view.text = _bobsPubKey.toHex()

            var pms:ByteArray?
            for (p in Security.getProviders("KeyAgreement.XDH")) {
                // Skip testing Android Keystore as it's covered by CTS tests.
                if ("AndroidKeyStore" == p.name) {
                    continue
                }
                prepareKeyStore(p)
                val ka: KeyAgreement = KeyAgreement.getInstance("XDH", p)
                pms = test_x25519_keyAgreement(ka)
                view = findViewById<View>(R.id.textView6) as TextView
                if (pms != null) {
                    view.text = pms.toHex()
                }
            }
            view = findViewById<View>(R.id.textView8) as TextView
            view.text = _expectedSecret.toHex()
        }
    }


    @Throws(java.lang.Exception::class)
    private fun test_x25519_keyAgreement(ka: KeyAgreement): ByteArray? {
        ka.init(rfc7748X25519PrivateKey)
        ka.doPhase(rfc7748X25519PublicKey, true)
        return ka.generateSecret()
    }

    private fun prepareKeyStore( p:Provider) {
        try {
            val kf = KeyFactory.getInstance("XDH", p)
            val privateKey: ByteArray = _alicesPrivKey
            this.rfc7748X25519PrivateKey = kf.generatePrivate(PKCS8EncodedKeySpec(privateKey))
            this.rfc7748X25519PublicKey = kf.generatePublic(X509EncodedKeySpec(_bobsPubKey))

        } catch (e: Exception) {
            Log.e(_tag, e.toString())
        }

    }

}