package com.example.androidthings.gattserver;

import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;

public class Package_Auth implements Serializable {

    byte[] OTP;
    SecretKeySpec Ksession;
    byte[] Package;
    byte[] Package_HMAC;

    public Package_Auth(byte[] OTP, SecretKeySpec ksession, byte[] aPackage, byte[] package_HMAC) {
        this.OTP = OTP;
        Ksession = ksession;
        Package = aPackage;
        Package_HMAC = package_HMAC;
    }
}
