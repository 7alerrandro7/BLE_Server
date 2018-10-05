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

import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;

import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.util.UUID;

import static android.bluetooth.BluetoothGattCharacteristic.*;

/**
 * Implementation of the Bluetooth GATT Custom Profile.
 * https://www.bluetooth.com/specifications/adopted-specifications
 */
public class CustomProfile {
    private static final String TAG = CustomProfile.class.getSimpleName();

    /* Current Security Service UUID */
    public static UUID SECURITY_SERVICE = UUID.fromString("00001805-0000-1000-8000-00805f9b34fb");
    /* Mandatory Read Information Characteristic */
    public static UUID CHARACTERISTIC_READ_UUID = UUID.fromString("00002a2b-0000-1000-8000-00805f9b34fb");
    /* Mandatory Write Information Characteristic */
    public static UUID CHARACTERISTIC_WRITE_UUID    = UUID.fromString("00000001-0000-1000-8000-00805f9b34fb");
    /* Optional Local Time Information Characteristic */
    //public static UUID LOCAL_TIME_INFO = UUID.fromString("00002a0f-0000-1000-8000-00805f9b34fb");
    /* Mandatory Client Characteristic Config Descriptor */
    public static UUID CLIENT_CONFIG = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    public static final String DATE_FORMAT_NOW = "dd-MM-yyyy HH:mm:ss";

    // Adjustment Flags
    public static final byte ADJUST_NONE     = 0x0;
    public static final byte ADJUST_MANUAL   = 0x1;
    public static final byte ADJUST_EXTERNAL = 0x2;
    public static final byte ADJUST_TIMEZONE = 0x4;
    public static final byte ADJUST_DST      = 0x8;

    /**
     * Return a configured {@link BluetoothGattService} instance for the
     * Current Time Service.
     */
    public static BluetoothGattService createSecurityService() {
        BluetoothGattService service = new BluetoothGattService(SECURITY_SERVICE, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        // Read characteristic
        BluetoothGattCharacteristic WriteCharacteristic = new BluetoothGattCharacteristic(CHARACTERISTIC_WRITE_UUID,
                PROPERTY_WRITE_NO_RESPONSE | PROPERTY_WRITE | PROPERTY_NOTIFY, PERMISSION_WRITE | PERMISSION_READ);

        // Read characteristic
        BluetoothGattCharacteristic ReadCharacteristic = new BluetoothGattCharacteristic(CHARACTERISTIC_READ_UUID,
                //Read-only characteristic, supports notifications
                PROPERTY_READ | PROPERTY_NOTIFY, PERMISSION_READ);

        BluetoothGattDescriptor configDescriptor = new BluetoothGattDescriptor(CLIENT_CONFIG,
                //Read/write descriptor
                BluetoothGattDescriptor.PERMISSION_READ | BluetoothGattDescriptor.PERMISSION_WRITE);
        ReadCharacteristic.addDescriptor(configDescriptor);

        // Local Time Information characteristic
        //BluetoothGattCharacteristic localTime = new BluetoothGattCharacteristic(LOCAL_TIME_INFO,
                //Read-only characteristic
                //PROPERTY_READ,
                //PERMISSION_READ);

        service.addCharacteristic(ReadCharacteristic);
        service.addCharacteristic(WriteCharacteristic);
        //service.addCharacteristic(localTime);

        return service;
    }


    /**
     * Catching the date_time now and sending like a byte[] array
     */
    public static byte[] getText() {
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
        String text = sdf.format(cal.getTime());
        byte [] b = text.getBytes();
        return b;
    }

}
