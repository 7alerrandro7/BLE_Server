package com.example.androidthings.gattserver;


import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

class SecurityClass {

    public static final String TAG = "SecurityKey_LOG";
    //final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    static byte[] Decrypt(byte[] text, SecretKeySpec Ksession){

        Cipher rc4 = null;
        try {
            rc4 = Cipher.getInstance("RC4");
            rc4.init(Cipher.DECRYPT_MODE, Ksession);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        byte[] cipherText = rc4.update(text);

        return(cipherText);
    }

    static byte[] Encrypt(String text, SecretKeySpec Ksession) {

        byte[] plainText = new byte[0];
        try {
            plainText = text.getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        Cipher rc4 = null;
        try {
            rc4 = Cipher.getInstance("RC4");
            rc4.init(Cipher.ENCRYPT_MODE, Ksession);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        byte [] cipherText = rc4.update(plainText);

        return(cipherText);

    }
}
