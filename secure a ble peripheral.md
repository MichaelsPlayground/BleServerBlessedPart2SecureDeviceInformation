# Secure a BLE peripheral

https://www.bluetooth.com/blog/bluetooth-pairing-part-1-pairing-feature-exchange/

https://www.bluetooth.com/blog/bluetooth-pairing-part-2-key-generation-methods/

https://www.bluetooth.com/blog/bluetooth-pairing-passkey-entry/

https://www.bluetooth.com/blog/bluetooth-pairing-part-4/

https://microchipdeveloper.com/wireless:ble-gap-security

https://devzone.nordicsemi.com/f/nordic-q-a/51437/gatt-database-configuration-in-server

https://sureshjoshi.com/development/bluetooth-low-energy-security

https://sureshjoshi.com/embedded/brute-force-pin-attacks-bgscript

https://technotes.kynetics.com/2018/BLE_Pairing_and_bonding/

https://medium.com/rtone-iot-security/deep-dive-into-bluetooth-le-security-d2301d640bfc

Characteristic mit pin, read write, store pin mit Mac Adress + name,  
falls pin ok werden daten ausgegeben sonst nicht. 

Nur device information wird ohne pin ausgegeben

Encryption with Libsodium SealedBox (https://stackoverflow.com/questions/42456624/how-can-i-create-or-open-a-libsodium-compatible-sealed-box-in-pure-java):

CpcJavaLibsodiumSealedCryptoboxEncryptionString: https://replit.com/@javacrypto/CpcJavaLibsodiumSealedCryptoboxEncryptionString#Main.java

JavaLibsodiumSealedBoxExample: https://replit.com/@javacrypto/JavaLibsodiumSealedBoxExample

uses: https://github.com/InstantWebP2P/tweetnacl-java/blob/master/src/main/java/com/iwebpp/crypto/TweetNacl.java

implementation "io.github.instantwebp2p:tweetnacl-java:1.1.2"

https://github.com/alphazero/Blake2b

or:

https://github.com/NeilMadden/salty-coffee + https://github.com/alphazero/Blake2b

```plaintext
Sealed boxes don't seem to be supported by salty-coffee (at least I haven't found a way). Therefore, and because I don't know of any pure Java library that supports sealed boxes, I use lazysodium (which is also a wrapper over the Libsodium library, though) to demonstrate the migration. For other libraries (even pure Java libraries, if there are any), this should be largely analogous:

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;

....

SodiumJava sodium = new SodiumJava();
LazySodiumJava lazySodium = new LazySodiumJava(sodium, StandardCharsets.UTF_8);

Key secretKey = Key.fromBase64String("0b9867Pq6sEdnxYM1ZscOhiMpruKn1Xg3xxB+wUF5eI=");
Key publicKey = Key.fromBase64String("xBC9lTyWdE/6EObv5NjryMbIvrviOzzPA+5XyM0QcHE=");

// Encryption
KeyPair keyPair = new KeyPair(publicKey, secretKey);
String ciphertext = lazySodium.cryptoBoxSealEasy("test", publicKey);
System.out.println(Base64.getEncoder().encodeToString(HexFormat.of().parseHex(ciphertext)));

// Decryption
String decrypted = lazySodium.cryptoBoxSealOpenEasy(ciphertext, keyPair);
System.out.println(decrypted);
If a ciphertext generated with this code is used as ciphertext in the Python code, it can be successfully decrypted, which shows that the encryption of both codes is functionally identical.

Edit:

As an alternative to another library, salty-coffee can be extended to support sealed boxes.

If the sender uses a sealed box, basically the following happens:

first, an ephemeral key pair is generated: ephemSK, ephemPK.
let PK be the public key of the receiver. A 24 bytes nonce is determined as follows: nonce = Blake2b(ephemPK || PK)
an encryption is performed with CryptoBox using ephemSK as secret key, PK as public key and the previously generated nonce.
CryptoBox returns the concatenation of ciphertext and the 16 bytes MAC. ephemPK is prepended to the ciphertext. The concatenation of these 3 parts is the result of the sealed box.
salty-coffee provides all Libsodium functionalities needed for the implementation except Blake2b. For this you can use e.g. Bouncycastle.

A possible implmentation is:

import software.pando.crypto.nacl.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import org.bouncycastle.crypto.digests.Blake2bDigest;

...

byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
  
// Sender's secret key SK, receiver's public key PK 
byte[] SK = Base64.getDecoder().decode("0b9867Pq6sEdnxYM1ZscOhiMpruKn1Xg3xxB+wUF5eI=");
byte[] PK = Base64.getDecoder().decode("xBC9lTyWdE/6EObv5NjryMbIvrviOzzPA+5XyM0QcHE="); 

// Create an ephemeral keypair: ephemSK, ephemPK
KeyPair ephemKeyPair = CryptoBox.keyPair();
byte[] ephemSK_pkcs8 = ephemKeyPair.getPrivate().getEncoded();
byte[] ephemPK_x509 = ephemKeyPair.getPublic().getEncoded();
byte[] ephemSK = getRawKey(ephemSK_pkcs8);
byte[] ephemPK = getRawKey(ephemPK_x509);

// Create the nonce = Blake2b(ephemeralPK || PK))
byte[] noncematerial = new byte[64];
System.arraycopy(ephemPK, 0, noncematerial, 0, ephemPK.length);
System.arraycopy(PK, 0, noncematerial, ephemPK.length, PK.length);  
byte[] nonce = new byte[24];
Blake2bDigest dig = new Blake2bDigest(null, nonce.length, null, null);
dig.update(noncematerial, 0, noncematerial.length);
dig.doFinal(nonce, 0);

// Encrypt with CryptoBox using ephemSK, PK and the nonce
CryptoBox cryptobox = CryptoBox.encrypt(CryptoBox.privateKey(ephemSK), CryptoBox.publicKey(PK), nonce, plaintext);
byte[] ciphertextMAC = cryptobox.getCiphertextWithTag();

// Prepend ephemPK
byte[] secretBoxSealed = new byte[ephemPK.length + ciphertextMAC.length];
System.arraycopy(ephemPK, 0, secretBoxSealed, 0, ephemPK.length);
System.arraycopy(ciphertextMAC, 0, secretBoxSealed, ephemPK.length, ciphertextMAC.length);
String secretBoxSealedB64 = Base64.getEncoder().encodeToString(secretBoxSealed);
System.out.println(secretBoxSealedB64); 
with:

// The raw keys are the last 32 bytes in PKCS#8 and X.509 formatted keys respectively.
private static byte[] getRawKey(byte[] key) {
    byte[] result = new byte[32];
    System.arraycopy(key, key.length - result.length, result, 0, result.length);
    return result;
}
A ciphertext created with this code can be successfully decrypted by the Python code above, proving the compatability.
Share
Edit
Follow
Flag
edited Mar 23 at 18:31
answered Mar 22 at 9:02
Topaco's user avatar
Topaco
```

To generate a Curve X25519 keypair see: https://github.com/java-crypto/cross_platform_crypto/blob/main/Curve25519KeyGeneration/GenerateCurve25519Keypair.java

needs an additional library: https://mvnrepository.com/artifact/org.whispersystems/curve25519-java/

// https://mvnrepository.com/artifact/org.whispersystems/curve25519-java
implementation group: 'org.whispersystems', name: 'curve25519-java', version: '0.5.0'


```plaintext
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GenerateCurve25519Keypair {
public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
System.out.println("Generate a key pair for Curve25519");
// you need this library
// https://github.com/signalapp/curve25519-java
// https://mvnrepository.com/artifact/org.whispersystems/curve25519-java
Curve25519KeyPair keyPair = generateCurve25519Keypair();
byte[] privateKey = keyPair.getPrivateKey();
byte[] publicKey = keyPair.getPublicKey();
System.out.println("base64 encoded key data:");
System.out.println("Curve25519 PrivateKey: " + base64Encoding(privateKey));
System.out.println("Curve25519 PublicKey:  " + base64Encoding(publicKey));
}

    public static Curve25519KeyPair generateCurve25519Keypair () {
        return Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
    }
    private static String base64Encoding(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }
}
```

or use TweetNaclFast.java

```plaintext
		/*
		 * @description
		 *   Generates a new random key pair for box and 
		 *   returns it as an object with publicKey and secretKey members:
		 * */
		public static KeyPair keyPair() {
			KeyPair kp = new KeyPair();

			crypto_box_keypair(kp.getPublicKey(), kp.getSecretKey());
			return kp;
		}

		public static KeyPair keyPair_fromSecretKey(byte [] secretKey) {
			KeyPair kp = new KeyPair();
			byte [] sk = kp.getSecretKey();
			byte [] pk = kp.getPublicKey();

			// copy sk
			for (int i = 0; i < sk.length; i ++)
				sk[i] = secretKey[i];

			crypto_scalarmult_base(pk, sk);
			return kp;
		}

	}
```


https://github.com/terl/lazysodium-java

with Android sample app: https://github.com/terl/lazysodium-android

