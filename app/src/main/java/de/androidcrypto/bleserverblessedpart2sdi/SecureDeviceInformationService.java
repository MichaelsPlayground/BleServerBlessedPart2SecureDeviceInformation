package de.androidcrypto.bleserverblessedpart2sdi;

import static android.bluetooth.BluetoothGattCharacteristic.PERMISSION_READ;
import static android.bluetooth.BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED_MITM;
import static android.bluetooth.BluetoothGattCharacteristic.PERMISSION_WRITE;
import static android.bluetooth.BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM;
import static android.bluetooth.BluetoothGattCharacteristic.PROPERTY_READ;
import static android.bluetooth.BluetoothGattCharacteristic.PROPERTY_WRITE;

import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;

import com.welie.blessed.BluetoothBytesParser;
import com.welie.blessed.BluetoothCentral;
import com.welie.blessed.BluetoothPeripheralManager;
import com.welie.blessed.GattStatus;
import com.welie.blessed.ReadResponse;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

import timber.log.Timber;

/**
 * this class is the original DeviceInformationService.java class but changed to work with a
 * PIN capability to check that the client is allowed to get data from the device
 */

class SecureDeviceInformationService extends BaseService {

    // changed
    private static final UUID SECURE_DEVICE_INFORMATION_SERVICE_UUID = UUID.fromString("0000180A-0000-1000-8000-00805f9b34fb");

    private static final UUID MANUFACTURER_NAME_CHARACTERISTIC_UUID = UUID.fromString("00002A29-0000-1000-8000-00805f9b34fb");
    private static final UUID MODEL_NUMBER_CHARACTERISTIC_UUID = UUID.fromString("00002A24-0000-1000-8000-00805f9b34fb");
    // new characteristics, the UUID are not an official UUID
    private static final UUID PIN_VERIFICATION_CHARACTERISTIC_UUID = UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb");
    private static final UUID PIN_VERIFICATION_STATUS_CHARACTERISTIC_UUID = UUID.fromString("0000ff02-0000-1000-8000-00805f9b34fb");
    BluetoothGattCharacteristic pinVerificationStatus = new BluetoothGattCharacteristic(PIN_VERIFICATION_STATUS_CHARACTERISTIC_UUID, PROPERTY_READ, PERMISSION_READ_ENCRYPTED_MITM);

    //private byte[] pinStored = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private byte[] pinStored = new byte[] {0x01, 0x02};
    private byte[] pinToVarify; // the pin to verify needs to be exact 8 bytes long
    private boolean pinVerificationStatusBoolean = false;

    // new
    private @NotNull final Handler handler = new Handler(Looper.getMainLooper());
    private @NotNull final Runnable notifyRunnable = this::notifyPinVerificationStatus;

    // changed
    private @NotNull final BluetoothGattService service = new BluetoothGattService(SECURE_DEVICE_INFORMATION_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

    public SecureDeviceInformationService(@NotNull BluetoothPeripheralManager peripheralManager) {
        super(peripheralManager);

        BluetoothGattCharacteristic manufacturer = new BluetoothGattCharacteristic(MANUFACTURER_NAME_CHARACTERISTIC_UUID, PROPERTY_READ, PERMISSION_READ);
        service.addCharacteristic(manufacturer);

        BluetoothGattCharacteristic modelNumber = new BluetoothGattCharacteristic(MODEL_NUMBER_CHARACTERISTIC_UUID, PROPERTY_READ, PERMISSION_READ);
        service.addCharacteristic(modelNumber);

        // new
        //BluetoothGattCharacteristic pinVerification = new BluetoothGattCharacteristic(PIN_VERIFICATION_CHARACTERISTIC_UUID, PROPERTY_WRITE, PERMISSION_WRITE);
        BluetoothGattCharacteristic pinVerification = new BluetoothGattCharacteristic(PIN_VERIFICATION_CHARACTERISTIC_UUID, PROPERTY_WRITE, PERMISSION_WRITE_ENCRYPTED_MITM);
        service.addCharacteristic(pinVerification);

        //BluetoothGattCharacteristic pinVerificationStatus = new BluetoothGattCharacteristic(PIN_VERIFICATION_STATUS_CHARACTERISTIC_UUID, PROPERTY_READ, PERMISSION_READ);

        service.addCharacteristic(pinVerificationStatus);
        pinVerificationStatus.addDescriptor(getClientCharacteristicConfigurationDescriptor());
    }

    // changed
    @Override
    public ReadResponse onCharacteristicRead(@NotNull BluetoothCentral central, @NotNull BluetoothGattCharacteristic characteristic) {
        if (characteristic.getUuid().equals(MANUFACTURER_NAME_CHARACTERISTIC_UUID)) {
            return new ReadResponse(GattStatus.SUCCESS, Build.MANUFACTURER.getBytes());
        } else if (characteristic.getUuid().equals(MODEL_NUMBER_CHARACTERISTIC_UUID)) {
            return new ReadResponse(GattStatus.SUCCESS, Build.MODEL.getBytes());
        } else if (characteristic.getUuid().equals(PIN_VERIFICATION_STATUS_CHARACTERISTIC_UUID)) {
            // check that the last entered pin is correct
            if (pinVerificationStatusBoolean) {
                return new ReadResponse(GattStatus.SUCCESS, "PIN IS CORRECT".getBytes(StandardCharsets.UTF_8));
            } else {
                return new ReadResponse(GattStatus.SUCCESS, "PIN IS NOT CORRECT".getBytes(StandardCharsets.UTF_8));
            }
        }
        return super.onCharacteristicRead(central, characteristic);
    }

    // new
    @Override
    public GattStatus onCharacteristicWrite(@NotNull BluetoothCentral central, @NotNull BluetoothGattCharacteristic characteristic, byte[] value) {
        // pin needs to be exact 8 bytes long
        if (value.length != 2) return GattStatus.VALUE_NOT_ALLOWED;
        BluetoothBytesParser parser = new BluetoothBytesParser(value, ByteOrder.LITTLE_ENDIAN);
        pinToVarify = parser.getValue().clone();
        return super.onCharacteristicWrite(central, characteristic, value);
    }

    // new
    @Override
    public void onCharacteristicWriteCompleted(@NonNull BluetoothCentral central, @NonNull BluetoothGattCharacteristic characteristic, @NonNull byte[] value) {
        Timber.d("pin to verify written %s", Arrays.toString(value));
        Timber.d("pin stored is         %s", Arrays.toString(pinStored));
        // verify for debug purposes
        if (Arrays.equals(pinToVarify, pinStored)) {
            pinVerificationStatusBoolean = true;
            Timber.d("pin to verify is correct");
        } else {
            pinVerificationStatusBoolean = false;
            Timber.d("pin to verify is NOT correct");
        }
        pinToVarify = new byte[0];
        super.onCharacteristicWriteCompleted(central, characteristic, value);
    }

    @Override
    public void onNotifyingEnabled(@NotNull BluetoothCentral central, @NotNull BluetoothGattCharacteristic characteristic) {
        if (characteristic.getUuid().equals(PIN_VERIFICATION_STATUS_CHARACTERISTIC_UUID)) {
            notifyPinVerificationStatus();
        }
    }

    @Override
    public void onNotifyingDisabled(@NotNull BluetoothCentral central, @NotNull BluetoothGattCharacteristic characteristic) {
        if (characteristic.getUuid().equals(PIN_VERIFICATION_STATUS_CHARACTERISTIC_UUID)) {
            stopNotifying();
        }
    }

    private void notifyPinVerificationStatus() {
        // check that the last entered pin is correct
        if (pinVerificationStatusBoolean) {
            //return new ReadResponse(GattStatus.SUCCESS, "PIN IS CORRECT".getBytes(StandardCharsets.UTF_8));
            notifyCharacteristicChanged("PIN IS CORRECT".getBytes(StandardCharsets.UTF_8), pinVerificationStatus);
            handler.postDelayed(notifyRunnable, 1000);
            Timber.i("pinVerificationStatus: %b", pinVerificationStatusBoolean);
        } else {
            notifyCharacteristicChanged("PIN IS NOT CORRECT".getBytes(StandardCharsets.UTF_8), pinVerificationStatus);
            handler.postDelayed(notifyRunnable, 1000);
            Timber.i("pinVerificationStatus: %b", pinVerificationStatusBoolean);
        }
    }

    private void stopNotifying() {
        handler.removeCallbacks(notifyRunnable);
    }

    @Override
    public @NotNull BluetoothGattService getService() {
        return service;
    }

    @Override
    public String getServiceName() {
        return "Device Information Service";
    }
}
