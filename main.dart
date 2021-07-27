import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/random/fortuna_random.dart';

import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

void main() {

  Uint8List passphrase = utf8.encode("The passphrase");
  Uint8List plaintext = utf8.encode("The quick brown fox jumps over the lazy dog");

  Uint8List ciphertext = AesGcmPbkdf2.encrypt(passphrase, plaintext);
  print(base64.encode(ciphertext)); // Example: 9LsGEs5hNyW0yX3LvS96UkviAH0EBi0nRTs8T15Rn4L8SZpEnDDyhSN+v8p7t+Arki1EnyZism2vUo0W779/eB2gASQ14sh7NM7Tmca9+Gy1W2zYXFDy

  Uint8List decryptedtext = AesGcmPbkdf2.decrypt(passphrase, ciphertext);
  print(utf8.decode(decryptedtext));
}

class AesGcmPbkdf2 {

  static int ALGORITHM_NONCE_SIZE = 12;
  static int ALGORITHM_TAG_SIZE = 128;
  static int ALGORITHM_KEY_SIZE = 128;
  static String PBKDF2_NAME = 'SHA-256/HMAC/PBKDF2';
  static int PBKDF2_SALT_SIZE = 16;
  static int PBKDF2_ITERATIONS = 32767;

  static Uint8List encrypt(Uint8List passphrase, Uint8List plaintext) {

    // Generate nonce and salt
    Random rnd = Random.secure(); // or any other CSPRNG like e.g. FortunaRandom
    Uint8List salt = getRandomData(rnd, PBKDF2_SALT_SIZE);
    Uint8List nonce = getRandomData(rnd, ALGORITHM_NONCE_SIZE);
    Uint8List aad = new Uint8List(0);

    // Derive key via PBKDF2
    Uint8List key = generateKey(salt, passphrase);

    // Encrypt with AES/GCM
    GCMBlockCipher encrypter = GCMBlockCipher(AESFastEngine());
    AEADParameters params = AEADParameters(KeyParameter(key), ALGORITHM_TAG_SIZE, nonce, aad);
    encrypter.init(true, params);
    Uint8List ciphertextTag = encrypter.process(plaintext);

    // Concat salt|nonce|ciphertext|tag
    BytesBuilder all = BytesBuilder();
    all.add(salt);
    all.add(nonce);
    all.add(ciphertextTag);

    return all.toBytes();
  }

  static Uint8List decrypt(Uint8List passphrase, Uint8List ciphertext) {

    // Separate salt, nonce and ciphertext|tag
    Uint8List salt = ciphertext.sublist(0, PBKDF2_SALT_SIZE);
    Uint8List nonce = ciphertext.sublist(PBKDF2_SALT_SIZE, PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
    Uint8List ciphertextTag = ciphertext.sublist(PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
    Uint8List aad = new Uint8List(0);

    // Derive key via PBKDF2
    Uint8List key = generateKey(salt, passphrase);

    // Decrypt with AES/GCM
    GCMBlockCipher decrypter = GCMBlockCipher(AESFastEngine());
    AEADParameters params = AEADParameters(KeyParameter(key), ALGORITHM_TAG_SIZE, nonce, aad);
    decrypter.init(false, params);
    Uint8List plaintext = decrypter.process(ciphertextTag);

    return plaintext;
  }

  static Uint8List getRandomData(Random rnd, int numberBytes){
    Uint8List data = Uint8List(numberBytes);
    for (int i = 0; i < numberBytes; i++) {
      data[i] = rnd.nextInt(256);
    }
    return data;
  }

  static Uint8List generateKey(Uint8List salt, Uint8List passphrase){
    var derivator = new KeyDerivator(PBKDF2_NAME);
    var params = new Pbkdf2Parameters(salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE~/8);
    derivator.init(params);
    return derivator.process(passphrase);
  }
  
}
