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
    /* Mandatory Get Hello Accepted Msg Read Information Characteristic */
    public static UUID GET_HELLO_UUID = UUID.fromString("00002a2b-0000-1000-8000-00405f6b34cb");
    /* Mandatory Get Mac Address Read Information Characteristic */
    public static UUID GET_MAC_UUID = UUID.fromString("00002a2b-0000-1000-8000-00805f9b34fb");
    /* Mandatory Auth Write Information Characteristic */
    public static UUID AUTH_WRITE_UUID = UUID.fromString("00000001-0000-1000-8000-00805f9b34fb");
    /* Mandatory Client Characteristic Config Descriptor */
    public static UUID CLIENT_CONFIG = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    // Adjustment Flags
    public static final byte ADJUST_NONE     = 0x0;
    public static final byte ADJUST_MANUAL   = 0x1;
    public static final byte ADJUST_TIMEZONE = 0x4;

    /**
     * Return a configured {@link BluetoothGattService} instance for the
     * Current Time Service.
     */
    public static BluetoothGattService createSecurityService() {
        BluetoothGattService service = new BluetoothGattService(SECURITY_SERVICE, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        // Read characteristic
        BluetoothGattCharacteristic AuthWriteCharacteristic = new BluetoothGattCharacteristic(AUTH_WRITE_UUID,
                WRITE_TYPE_DEFAULT | PROPERTY_WRITE | PROPERTY_READ, PERMISSION_WRITE | PERMISSION_READ);

        // Read characteristic
        BluetoothGattCharacteristic GetMacCharacteristic = new BluetoothGattCharacteristic(GET_MAC_UUID,
                //Read-only characteristic, supports notifications
                PROPERTY_READ, PERMISSION_READ);

        // Read characteristic
        BluetoothGattCharacteristic GetHelloCharacteristic = new BluetoothGattCharacteristic(GET_HELLO_UUID,
                //Read-only characteristic, supports notifications
                PROPERTY_READ, PERMISSION_READ);

        BluetoothGattDescriptor configDescriptor = new BluetoothGattDescriptor(CLIENT_CONFIG,
                //Read/write descriptor
                BluetoothGattDescriptor.PERMISSION_READ | BluetoothGattDescriptor.PERMISSION_WRITE);
        GetMacCharacteristic.addDescriptor(configDescriptor);

        service.addCharacteristic(GetHelloCharacteristic);
        service.addCharacteristic(GetMacCharacteristic);
        service.addCharacteristic(AuthWriteCharacteristic);

        return service;
    }

}
