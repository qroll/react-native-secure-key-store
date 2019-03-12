package com.reactlibrary.securekeystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class WorkaroundHelper {

    private static String ENCRYPT_DECRYPT_PROVIDER = "AndroidOpenSSL";
    private static String SHARED_PREF_DEFAULT_KEYPAIR_GEN = "DEFAULT_KEYPAIR_GEN";

    private static String ERROR_GMS_CERT = "can't generate certificate";
    private static String MODEL_OPPO = "X9079";

    public static X509Certificate buildX509Certificate(String alias, Calendar notBefore, Calendar notAfter, PrivateKey privKey, PublicKey pubKey) throws Exception {
        SecureRandom random = new SecureRandom();
        BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()));

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, alias);
        nameBuilder.addRDN(BCStyle.O, "MOE");
        nameBuilder.addRDN(BCStyle.OU, "PG");
        nameBuilder.addRDN(BCStyle.C, "SG");
        nameBuilder.addRDN(BCStyle.L, "Singapore");

        X500Name issuer = nameBuilder.build();
        X500Name subject = issuer;

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serialNumber, notBefore.getTime(), notAfter.getTime(), subject, SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = builder.build(privKey);

        byte[] certBytes = certBuilder.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        return certificate;
    }

    public static boolean isNotWorkaround(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(Constants.TAG, Context.MODE_PRIVATE);
        return prefs.getBoolean(SHARED_PREF_DEFAULT_KEYPAIR_GEN, true);
    }

    public static boolean shouldEnableWorkaround(Exception e) {
        return e.getMessage().toLowerCase().contains(ERROR_GMS_CERT) && Build.MODEL.equals(MODEL_OPPO);
    }

    public static void enableWorkaround(Context context) {
        SharedPreferences.Editor editor = context.getSharedPreferences(Constants.TAG, Context.MODE_PRIVATE).edit();
        editor.putBoolean(SHARED_PREF_DEFAULT_KEYPAIR_GEN, false);
        editor.apply();
    }

    public static Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        return Cipher.getInstance(Constants.RSA_ALGORITHM, ENCRYPT_DECRYPT_PROVIDER);
    }

}
