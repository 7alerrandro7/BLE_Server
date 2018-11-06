package com.example.androidthings.gattserver;

import android.bluetooth.BluetoothDevice;

import javax.crypto.spec.SecretKeySpec;

public class ConnectedHub {

    public BluetoothDevice hub;
    public int STATE;
    public byte[] pack = new byte[60];
    int lastPackSize;
    boolean Authenticated;
    byte[] OTP;
    byte[] timestamp;
    byte[] AcceptedMessage = null;
    SecretKeySpec Ksession;

    public ConnectedHub(BluetoothDevice hub, int lastPackSize) {
        this.hub = hub;
        this.STATE = 1;
        this.Authenticated = false;
        this.lastPackSize = lastPackSize;
    }

    public void setAuthenticated(boolean authenticated) {
        Authenticated = authenticated;
    }

    public void setKsession(SecretKeySpec ksession) {
        Ksession = ksession;
    }

    public void setOTP(byte[] OTP) {
        this.OTP = OTP;
    }

    public void setTimestamp(byte[] timestamp) {
        this.timestamp = timestamp;
    }

    public void setAcceptedMessage(byte[] acceptedMessage) {
        AcceptedMessage = acceptedMessage;
    }
}
