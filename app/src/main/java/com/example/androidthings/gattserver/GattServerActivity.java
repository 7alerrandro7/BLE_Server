/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.androidthings.gattserver;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.ParcelUuid;
import android.util.Log;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class GattServerActivity extends Activity {
    private static final String TAG = GattServerActivity.class.getSimpleName();

    /* Local UI */
    private TextView mDataField_Security;
    private TextView mDataField;
    private ListView mList;
    /* Bluetooth API */
    private BluetoothManager mBluetoothManager;
    private BluetoothGattServer mBluetoothGattServer;
    private BluetoothLeAdvertiser mBluetoothLeAdvertiser;
    /* Collection of notification subscribers */
    private Set<BluetoothDevice> mRegisteredDevices = new HashSet<>();
    private ArrayList<ConnectedHub> ConnectedHubList = new ArrayList<>();

    private ArrayAdapter arrayAdapter;

    private String obj_id = getBluetoothMacAddress();


    /* Symetric Authentication Key SDDL and S-Obj */
    private static SecretKeySpec Kauth_sddl;
    private static byte[] Kauth_obj;

    /* Symetric Cipher Key (S-OBJ)*/
    private byte[] Kcipher_obj = "Kcipher_obj".getBytes("ASCII");

    /* Initializing Authentications Keys */
    static {
        try {
            Kauth_sddl = new SecretKeySpec(("Kauth_sddl").getBytes("ASCII"), "hmacMD5");
            Kauth_obj = ("Kauth_obj").getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }


    public GattServerActivity() throws UnsupportedEncodingException {
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_server);

        mList = findViewById(R.id.usrAuth);
        arrayAdapter = new ConnectedHubAdapter(this, ConnectedHubList);
        mList.setAdapter(arrayAdapter);

        // Devices with a display should not go to sleep
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        mBluetoothManager = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
        BluetoothAdapter bluetoothAdapter = mBluetoothManager.getAdapter();
        // We can't continue without proper Bluetooth support
        if (!checkBluetoothSupport(bluetoothAdapter)) {
            finish();
        }

        // Register for system Bluetooth events
        IntentFilter filter = new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED);
        registerReceiver(mBluetoothReceiver, filter);
        if (!bluetoothAdapter.isEnabled()) {
            Log.d(TAG, "Bluetooth is currently disabled...enabling");
            bluetoothAdapter.enable();
        } else {
            Log.d(TAG, "Bluetooth enabled...starting services");
            startAdvertising();
            startServer();
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
    }

    @Override
    protected void onStop() {
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        BluetoothAdapter bluetoothAdapter = mBluetoothManager.getAdapter();
        if (bluetoothAdapter.isEnabled()) {
            stopServer();
            stopAdvertising();
        }

        unregisterReceiver(mBluetoothReceiver);
    }

    /**
     * Verify the level of Bluetooth support provided by the hardware.
     * @param bluetoothAdapter System {@link BluetoothAdapter}.
     * @return true if Bluetooth is properly supported, false otherwise.
     */
    private boolean checkBluetoothSupport(BluetoothAdapter bluetoothAdapter) {

        if (bluetoothAdapter == null) {
            Log.w(TAG, "Bluetooth is not supported");
            return false;
        }

        if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
            Log.w(TAG, "Bluetooth LE is not supported");
            return false;
        }

        return true;
    }

    /**
     * Listens for Bluetooth adapter events to enable/disable
     * advertising and server functionality.
     */
    private BroadcastReceiver mBluetoothReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            int state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_OFF);

            switch (state) {
                case BluetoothAdapter.STATE_ON:
                    startAdvertising();
                    startServer();
                    break;
                case BluetoothAdapter.STATE_OFF:
                    stopServer();
                    stopAdvertising();
                    break;
                default:
                    // Do nothing
            }

        }
    };

    /**
     * Begin advertising over Bluetooth that this device is connectable
     * and supports the Current Time Service.
     */
    private void startAdvertising() {
        BluetoothAdapter bluetoothAdapter = mBluetoothManager.getAdapter();
        mBluetoothLeAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        if (mBluetoothLeAdvertiser == null) {
            Log.w(TAG, "Failed to create advertiser");
            return;
        }

        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();

        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(true)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(new ParcelUuid(CustomProfile.SECURITY_SERVICE))
                .build();

        mBluetoothLeAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
    }

    /**
     * Stop Bluetooth advertisements.
     */
    private void stopAdvertising() {
        if (mBluetoothLeAdvertiser == null) return;

        mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
    }

    /**
     * Initialize the GATT server instance with the services/characteristics
     * from the Time Profile.
     */
    private void startServer() {
        mBluetoothGattServer = mBluetoothManager.openGattServer(this, mGattServerCallback);
        if (mBluetoothGattServer == null) {
            Log.w(TAG, "Unable to create GATT server");
            return;
        }
        mBluetoothGattServer.addService(CustomProfile.createSecurityService());
    }

    /**
     * Shut down the GATT server.
     */
    private void stopServer() {
        if (mBluetoothGattServer == null) return;

        mBluetoothGattServer.close();
    }

    /**
     * Callback to receive information about the advertisement process.
     */
    private AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.i(TAG, "LE Advertise Started.");
        }

        @Override
        public void onStartFailure(int errorCode) {
            Log.w(TAG, "LE Advertise Failed: "+errorCode);
        }
    };

    /**
     * Send a time service notification to any devices that are subscribed
     * to the characteristic.
     */
    private void notifyRegisteredDevices(long timestamp, byte adjustReason) {
        if (mRegisteredDevices.isEmpty()) {
            Log.i(TAG, "No subscribers registered");
            return;
        }

        Log.i(TAG, "Sending update to " + mRegisteredDevices.size() + " subscribers");
        for (BluetoothDevice device : mRegisteredDevices) {
            BluetoothGattCharacteristic securitySendCharacteristic = mBluetoothGattServer
                    .getService(CustomProfile.SECURITY_SERVICE)
                    .getCharacteristic(CustomProfile.GET_MAC_UUID);

            BluetoothGattCharacteristic securityReceiveCharacteristic = mBluetoothGattServer
                    .getService(CustomProfile.SECURITY_SERVICE)
                    .getCharacteristic(CustomProfile.AUTH_WRITE_UUID);

            mBluetoothGattServer.notifyCharacteristicChanged(device, securitySendCharacteristic, false);
            mBluetoothGattServer.notifyCharacteristicChanged(device, securityReceiveCharacteristic, false);
        }
    }

    /**
     * Update graphical UI on devices.
     */
    private void updateLocalUi2(final String value) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                mDataField = findViewById(R.id.Rdata);
                mDataField.setText(value);
            }
        });
    }

    private void updateLocalUi(final String value) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                mDataField_Security = findViewById(R.id.security_value);
                mDataField_Security.setText(value);
            }
        });
    }

    private void updateList() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                arrayAdapter.notifyDataSetChanged();
            }
        });
    }

    private boolean RemoveConnectedHub(BluetoothDevice device){
        for(int i = 0; i< ConnectedHubList.size(); i++){
            if(ConnectedHubList.get(i).getHub().equals(device)){
                ConnectedHubList.remove(ConnectedHubList.get(i));
                return true;
            }
        }
        return false;
    }

    //Função que gera a chave para gerar o HASH da mesagem HelloMessage
    private SecretKeySpec Generate_Hub_Auth_Key(byte[] OTP){
        SecretKeySpec Kauth_hub = new SecretKeySpec(OTP, "RC4");
        return Kauth_hub;
    }

    //Função que gera o hash do Hub_Id + A HelloMessage
    private byte[] GenerateHMAC(String hub_id, byte[] HM, SecretKeySpec Kauth_hub){
        byte[] Hello_Message_HMAC = new byte[0];
        String pack = null;
        try {
            pack = hub_id + new String(HM, "ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        Log.d(TAG, "Hub_ID:" + hub_id);
        Log.d(TAG, "HelloMessage:" + HM);
        Log.d(TAG, "PACK:" + pack);

        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_hub);

            Hello_Message_HMAC = mac.doFinal(pack.getBytes("ASCII"));

        } catch (UnsupportedEncodingException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }

        return Hello_Message_HMAC;
    }

    //Função que gera o hash do Accepted Message
    private byte[] GenerateHMAC(String hub_id, String obj_id, byte[] Timestamp, SecretKeySpec Kauth_hub){
        byte[] Hello_Accepted_Message_HMAC = new byte[0];
        String pack = null;
        try {
            pack = hub_id + obj_id + new String(Timestamp, "ASCII");
            Log.d(TAG, "PACKKK: " + pack);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_hub);

            Hello_Accepted_Message_HMAC = mac.doFinal(pack.getBytes("ASCII"));

        } catch (UnsupportedEncodingException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }

        return Hello_Accepted_Message_HMAC;
    }


    private boolean CheckSignForHelloMessage(String hub_id, byte[] OTP, byte[] HelloMessage, byte[] HelloMessage_HASH){
        SecretKeySpec Kauth_hub = Generate_Hub_Auth_Key(OTP);
        byte[] HelloMessage_HMAC = GenerateHMAC(hub_id, HelloMessage, Kauth_hub);
        Log.d(TAG, "HelloMessage_HMAC: ");
        print_hex(HelloMessage_HMAC);

        Log.d(TAG, "HelloMessage_HASH: ");
        print_hex(HelloMessage_HASH);

        if(Arrays.equals(HelloMessage_HASH, HelloMessage_HMAC)){
            return true;
        }
        return false;
    }

    private boolean CheckSignForPackage(byte[] PackageK, byte[] Package_K_With_HMAC, SecretKeySpec Kauth_sddl){
        byte[] PackageK_HASH = new byte[0];
        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_sddl);
            PackageK_HASH = mac.doFinal(PackageK);
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }

        if(Arrays.equals(PackageK_HASH, Package_K_With_HMAC)){
            return true;
        }
        return false;
    }

    private byte[] CheckAuthentication(ConnectedHub Hub){
        print_hex(Hub.getPack());
        byte[] PackageK = Arrays.copyOfRange(Hub.getPack(), 0, 24);
        Log.d(TAG, "PackageK: ");
        print_hex(PackageK);
        byte[] Package_K_With_HMAC = Arrays.copyOfRange(Hub.getPack(), 24, 40);
        Log.d(TAG, "PackageK_HMAC: ");
        print_hex(Package_K_With_HMAC);
        boolean CheckSign = CheckSignForPackage(PackageK, Package_K_With_HMAC, Kauth_sddl);
        if(CheckSign) {
            return PackageK;
        }else{
            return null;
        }
    }

    private byte[] Decrypt(byte[] Package, byte[] Kcipher_obj) {

        Cipher rc4 = null;
        try {
            rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(Kcipher_obj, "RC4");
            rc4.init(Cipher.DECRYPT_MODE, rc4Key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte [] cipherText = rc4.update(Package);

        return(cipherText);
    }

    private byte[] generateOTP(String obj_id, String hub_id, String OTPChallenge, byte[] Kauth_obj){
        String KAUTH = null;
        try {
            KAUTH = new String(Kauth_obj, "ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String concat = obj_id + hub_id + OTPChallenge + KAUTH;
        Log.d(TAG, "STRING OTP: " + concat);

        byte[] OTP = new byte[0];
        try {
            OTP = concat.getBytes("UTF8");
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(OTP);
            OTP = messageDigest.digest();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return OTP;
    }

    private byte[] signHelloAcceptedMessage(String hub_id, byte[] OTP, byte[] TimeStamp){
        SecretKeySpec Kauth_hub = Generate_Hub_Auth_Key(OTP);
        byte[] Hello_Accepted_Message_HMAC = GenerateHMAC(hub_id, obj_id, TimeStamp, Kauth_hub);
        Log.d(TAG, "Hello_Accepted_Message_HMAC: ");
        print_hex(Hello_Accepted_Message_HMAC);
        return Hello_Accepted_Message_HMAC;
    }


    public void print_hex(byte[] cipherText) {
        if(cipherText != null){
            StringBuffer buf = new StringBuffer();
            for(int i = 0; i < cipherText.length; i++) {
                String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
                buf.append((hex.length() < 2 ? "0" : "") + hex);
            }

            // imprime o ciphertext em hexadecimal
            Log.i(TAG, "Texto bytes: " + buf.toString());
        }
    }

    private String getBluetoothMacAddress() {
        BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        String bluetoothMacAddress = "";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M){
            try {
                Field mServiceField = bluetoothAdapter.getClass().getDeclaredField("mService");
                mServiceField.setAccessible(true);
                Object btManagerService = mServiceField.get(bluetoothAdapter);
                if (btManagerService != null) {
                    bluetoothMacAddress = (String) btManagerService.getClass().getMethod("getAddress").invoke(btManagerService);
                }
            } catch (NoSuchFieldException e) {
            } catch (NoSuchMethodException e) {
            } catch (IllegalAccessException e) {
            } catch (InvocationTargetException e) {
            }
        } else {
            bluetoothMacAddress = bluetoothAdapter.getAddress();
        }
        return bluetoothMacAddress;
    }


    /**
     * Callback to handle incoming requests to the GATT server.
     * All read/write requests for characteristics and descriptors are handled here.
     */
    private BluetoothGattServerCallback mGattServerCallback = new BluetoothGattServerCallback(){

        public void onCharacteristicWriteRequestSecurity(BluetoothDevice device, int requestId, BluetoothGattCharacteristic characteristic,
                                                 boolean preparedWrite, boolean responseNeeded, int offset, byte[] value) {

        }

        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "BluetoothDevice CONNECTED: " + device);
                ConnectedHubList.add(new ConnectedHub(device, 0));

            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.i(TAG, "BluetoothDevice DISCONNECTED: " + device);
                //Remove device from any active subscriptions
                RemoveConnectedHub(device);
                mRegisteredDevices.remove(device);
                updateList();
            }
        }

        @Override
        public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId, BluetoothGattCharacteristic characteristic,
                                                 boolean preparedWrite, boolean responseNeeded, int offset, byte[] value) {
            if (value != null) {
                if (CustomProfile.AUTH_WRITE_UUID.equals(characteristic.getUuid())) {
                    for (int i = 0; i < ConnectedHubList.size(); i++) {
                        if (ConnectedHubList.get(i).getHub().equals(device) && ConnectedHubList.get(i).isAuthenticated() == false) {
                            int lastPackSize = ConnectedHubList.get(i).getLastPackSize();
                            switch (ConnectedHubList.get(i).getSTATE()) {
                                case 1:
                                    Log.d(TAG, "STATE 1");
                                    System.arraycopy(value, 0, ConnectedHubList.get(i).getPack(), ConnectedHubList.get(i).getLastPackSize(), value.length);
                                    ConnectedHubList.get(i).setLastPackSize(lastPackSize + value.length);
                                    ConnectedHubList.get(i).setSTATE(2);
                                    mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, "ok".getBytes());
                                    break;
                                case 2:
                                    Log.d(TAG, "STATE 2");
                                    System.arraycopy(value, 0, ConnectedHubList.get(i).getPack(), ConnectedHubList.get(i).getLastPackSize(), value.length);
                                    ConnectedHubList.get(i).setLastPackSize(lastPackSize + value.length);
                                    ConnectedHubList.get(i).setSTATE(3);
                                    mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, "ok".getBytes());
                                    break;
                                case 3:
                                    Log.d(TAG, "STATE 3");
                                    System.arraycopy(value, 0, ConnectedHubList.get(i).getPack(), ConnectedHubList.get(i).getLastPackSize(), value.length);
                                    ConnectedHubList.get(i).setLastPackSize(lastPackSize + value.length);
                                    ConnectedHubList.get(i).setSTATE(4);
                                    byte[] PackageK = CheckAuthentication(ConnectedHubList.get(i));
                                    if (PackageK != null) {
                                        ConnectedHubList.get(i).setAuthenticated(true);

                                        /* Getting PackageK Decrypted */
                                        byte[] PackageK_Decrypted = Decrypt(PackageK, Kcipher_obj);

                                        /* Getting the hub_id and obj_id */
                                        String hub_id = ConnectedHubList.get(i).getHub_fixID();

                                        /* Creating OTP */
                                        String OTPChallenge = null;
                                        try {
                                            OTPChallenge = new String(Arrays.copyOfRange(PackageK_Decrypted, 0, 13), "ASCII");
                                        } catch (UnsupportedEncodingException e) {
                                            e.printStackTrace();
                                        }
                                        byte[] OTP = generateOTP(obj_id, hub_id, OTPChallenge, Kauth_obj);

                                        /* Getting the HelloMessage and HelloMessage_HMAC */
                                        byte[] HelloMessage = Arrays.copyOfRange(ConnectedHubList.get(i).getPack(), 0, 44);
                                        byte[] HelloMessage_HMAC = Arrays.copyOfRange(ConnectedHubList.get(i).getPack(), 44, 60);

                                        if (CheckSignForHelloMessage(hub_id, OTP, HelloMessage, HelloMessage_HMAC)) {
                                            Log.d(TAG, "Mensagem assinada corretamente!");

                                            /* Setting the Session Key on the Database */
                                            byte[] Key_session = Arrays.copyOfRange(PackageK_Decrypted, 13, PackageK_Decrypted.length);
                                            SecretKeySpec Ksession = new SecretKeySpec(Key_session, 0, Key_session.length, "RC4");
                                            ConnectedHubList.get(i).setKsession(Ksession);

                                            /* Setting OTPChallenge on the Database */
                                            ConnectedHubList.get(i).setOTP(OTP);

                                            /* Setting TimeStamp on the Database */
                                            byte[] timestamp = Arrays.copyOfRange(ConnectedHubList.get(i).getPack(), 40, 44);
                                            ConnectedHubList.get(i).setTimestamp(timestamp);

                                            ConnectedHubList.get(i).setAcceptedMessage(signHelloAcceptedMessage(hub_id, OTP, timestamp));

                                            mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, "ok".getBytes());

                                            updateLocalUi2("Último cliente " + device.getName() + " autenticado com sucesso!");

                                            updateList();

                                        } else {
                                            Log.d(TAG, "Falha na Verificação da Assinatura");
                                        }
                                        updateLocalUi(HelloMessage_HMAC.toString());
                                    }
                            }
                            return;
                        }
                    }

                    //Log.i(TAG, responseNeeded + " VALOOORRRR:" + text);
                    //updateLocalUi(text);
                }
                if (CustomProfile.SET_MAC_UUID.equals(characteristic.getUuid())) {
                    for (int i = 0; i < ConnectedHubList.size(); i++) {
                        if (ConnectedHubList.get(i).getHub().equals(device) && ConnectedHubList.get(i).isAuthenticated() == false) {
                            try {
                                Log.d(TAG, "Receving MacAddress");
                                ConnectedHubList.get(i).setHub_fixID(new String(value, "ASCII"));
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                            }
                            mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, "ok".getBytes());
                            Log.d(TAG, "REsponse!!!!!");
                            return;
                        }
                    }
                }
                for (int i = 0; i < ConnectedHubList.size(); i++) {
                    if (ConnectedHubList.get(i).getHub().equals(device) && ConnectedHubList.get(i).isAuthenticated() == true) {
                        // HUB trying to write on SmartObject
                        return;
                    }
                }
                onCharacteristicWriteRequestSecurity(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value);
            } else {
                Log.w(TAG, "Null value!");
                return;
            }
        }

        @Override
        public void onCharacteristicReadRequest(BluetoothDevice device, int requestId, int offset, BluetoothGattCharacteristic characteristic) {
            if (CustomProfile.GET_MAC_UUID.equals(characteristic.getUuid())) {
                Log.i(TAG, "Read MAC Address of IoT");

                byte[] MacAddress = getBluetoothMacAddress().getBytes();

                Log.i(TAG, "BYTES = " + MacAddress);
                mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, MacAddress);

            } else if(CustomProfile.GET_HELLO_UUID.equals(characteristic.getUuid())){
                for(int i = 0; i < ConnectedHubList.size(); i++) {
                    if (ConnectedHubList.get(i).getHub().equals(device) && ConnectedHubList.get(i).isAuthenticated() == true) {
                        mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, ConnectedHubList.get(i).getAcceptedMessage());
                    }
                }
            } else if(CustomProfile.READ_UUID.equals(characteristic.getUuid())){
                for(int i = 0; i < ConnectedHubList.size(); i++) {
                    if (ConnectedHubList.get(i).getHub().equals(device) && ConnectedHubList.get(i).isAuthenticated() == true) {
                        EditText text_field;
                        text_field = findViewById(R.id.plain_text_input);
                        String text = text_field.getText().toString();

                        byte [] text_in_bytes = new byte[0];
                        try {
                            text_in_bytes = SecurityClass.Encrypt(text, ConnectedHubList.get(i).getKsession());
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        } catch (InvalidKeyException e) {
                            e.printStackTrace();
                        } catch (NoSuchPaddingException e) {
                            e.printStackTrace();
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                        mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, text_in_bytes);
                    }
                }
            } else {
                // Invalid characteristic
                Log.w(TAG, "Invalid Characteristic Read: " + characteristic.getUuid());
                super.onCharacteristicReadRequest(device, requestId, offset, characteristic);
                //mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null);
            }
        }

        @Override
        public void onDescriptorReadRequest(BluetoothDevice device, int requestId, int offset, BluetoothGattDescriptor descriptor) {
            if (CustomProfile.CLIENT_CONFIG.equals(descriptor.getUuid())) {
                Log.d(TAG, "Config descriptor read");
                byte[] returnValue;
                if (mRegisteredDevices.contains(device)) {
                    returnValue = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE;
                } else {
                    returnValue = BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE;
                }
                mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, returnValue);
            } else {
                Log.w(TAG, "Unknown descriptor read request");
                mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null);
            }
        }

        @Override
        public void onDescriptorWriteRequest(BluetoothDevice device, int requestId, BluetoothGattDescriptor descriptor, boolean preparedWrite, boolean responseNeeded, int offset, byte[] value) {
            if (CustomProfile.CLIENT_CONFIG.equals(descriptor.getUuid())) {
                if (Arrays.equals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, value)) {
                    Log.d(TAG, "Subscribe device to notifications: " + device);
                    mRegisteredDevices.add(device);
                } else if (Arrays.equals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE, value)) {
                    Log.d(TAG, "Unsubscribe device from notifications: " + device);
                    mRegisteredDevices.remove(device);
                }

                if (responseNeeded) {
                    mBluetoothGattServer.sendResponse(device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            0,
                            null);
                }
            } else {
                Log.w(TAG, "Unknown descriptor write request");
                if (responseNeeded) {
                    mBluetoothGattServer.sendResponse(device,
                            requestId,
                            BluetoothGatt.GATT_FAILURE,
                            0,
                            null);
                }
            }
        }
    };
}
