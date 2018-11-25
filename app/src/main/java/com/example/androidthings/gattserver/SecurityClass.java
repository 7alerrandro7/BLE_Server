package com.example.androidthings.gattserver;


import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SecurityClass {

    public static final String TAG = "SecurityKey_LOG";
    //final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    public static String Decrypt(byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {


        Log.d(TAG, "Bytes = " + text.toString());

        byte [] key = "AAAAA".getBytes("ASCII");

        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        rc4.init(Cipher.DECRYPT_MODE, rc4Key);

        byte [] cipherText = rc4.update(text);

        return(new String(cipherText, "ASCII"));

    }

    public static void Decrypt(byte[] text, SecretKeySpec Ksession){

        Cipher rc4 = null;
        try {
            rc4 = Cipher.getInstance("RC4");
            rc4.init(Cipher.DECRYPT_MODE, Ksession);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte [] cipherText = rc4.update(text);
        Log.d(TAG, "Texto Limpo: " + cipherText);

        return;

    }

    public static byte[] Encrypt(String text) throws UnsupportedEncodingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        byte[] plainText = text.getBytes("ASCII");

        Log.i(TAG, text);

        byte [] key = "AAAAA".getBytes("ASCII");

        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        rc4.init(Cipher.ENCRYPT_MODE, rc4Key);

        byte [] cipherText = rc4.update(plainText);

        // converte o cipherText para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < cipherText.length; i++) {
            String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        // imprime o ciphertext em hexadecimal
        Log.i(TAG, buf.toString());

        return(cipherText);

    }

    public static byte[] Encrypt(String text, SecretKeySpec Ksession) throws UnsupportedEncodingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        byte[] plainText = text.getBytes("ASCII");

        Log.i(TAG, text);

        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.ENCRYPT_MODE, Ksession);

        byte [] cipherText = rc4.update(plainText);

        // converte o cipherText para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < cipherText.length; i++) {
            String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        // imprime o ciphertext em hexadecimal
        Log.i(TAG, buf.toString());

        return(cipherText);

    }
}
