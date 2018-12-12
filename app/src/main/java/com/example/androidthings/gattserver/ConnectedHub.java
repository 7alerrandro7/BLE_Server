package com.example.androidthings.gattserver;

import android.bluetooth.BluetoothDevice;

import javax.crypto.spec.SecretKeySpec;

public class ConnectedHub {

    private BluetoothDevice hub;
    private String hub_fixID;
    private int STATE;
    private byte[] pack = new byte[60];
    private int lastPackSize;
    private boolean Authenticated;
    private byte[] OTP;
    private byte[] timestamp;
    private byte[] AcceptedMessage = null;
    private String message;
    private SecretKeySpec Ksession;

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

    public BluetoothDevice getHub() {
        return hub;
    }

    public void setHub(BluetoothDevice hub) {
        this.hub = hub;
    }

    public int getSTATE() {
        return STATE;
    }

    public void setSTATE(int STATE) {
        this.STATE = STATE;
    }

    public byte[] getPack() {
        return pack;
    }

    public void setPack(byte[] pack) {
        this.pack = pack;
    }

    public int getLastPackSize() {
        return lastPackSize;
    }

    public void setLastPackSize(int lastPackSize) {
        this.lastPackSize = lastPackSize;
    }

    public boolean isAuthenticated() {
        return Authenticated;
    }

    public byte[] getOTP() {
        return OTP;
    }

    public byte[] getTimestamp() {
        return timestamp;
    }

    public byte[] getAcceptedMessage() {
        return AcceptedMessage;
    }

    public SecretKeySpec getKsession() {
        return Ksession;
    }

    public String getHub_fixID() {
        return hub_fixID;
    }

    public void setHub_fixID(String hub_fixID) {
        this.hub_fixID = hub_fixID;
    }

    public String getMessage() { return message; }

    public void setMessage(String message) { this.message = message; }
}
