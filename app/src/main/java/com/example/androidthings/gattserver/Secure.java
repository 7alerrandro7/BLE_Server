package com.example.androidthings.gattserver;


import android.os.Environment;
import android.util.Log;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;
import javax.crypto.*;

public class Secure {

    public static final String TAG = "SecurityKey_LOG";
    final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    public static byte[] Encrypt(String text) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeyException {

        byte[] plainText = text.getBytes("UTF8");

        Log.i(TAG, text);

        //
        // Recuperando a key de um arquivo
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(path + "KeyFile.key"));
        Key key = (Key)in.readObject();
        in.close();

        //
        // define um objeto de cifra DES e imprime o provider utilizado
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //
        // encripta utilizando a chave e o texto plano
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);

        return(cipherText);

    }

}
