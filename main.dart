import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:pointycastle/export.dart';

void main() {
  
  final passphrase = utf8.encode("Some passphrase");
  final plaintext = utf8.encode("The quick brown fox jumps over the lazy dog");
  final aad = utf8.encode("Some additional authenticated data (AAD)");

  final ciphertext = AesGcmPbkdf2.encrypt(passphrase, plaintext, aad);
  print(base64.encode(ciphertext)); // Example: zAY+zkMmRCdMB6FZCluJuF+WS3WwWARSqE9ajroUndPOuu3Zj6qGVSP/vklVOjgia29oJ+RfD8lYFYNQRTv8lJHjHx8vTqwxCcVx9xlfvOFD23k56zg9

  final decryptedtext = AesGcmPbkdf2.decrypt(passphrase, ciphertext, aad);
  print(utf8.decode(decryptedtext));
}

class AesGcmPbkdf2 {

  static const ALGORITHM_NONCE_SIZE = 12; // bytes
  static const ALGORITHM_TAG_SIZE = 16; // bytes
  static const ALGORITHM_KEY_SIZE = 32; // bytes
  static const PBKDF2_PRF_DIGEST = 'SHA-256/HMAC/PBKDF2';
  static const PBKDF2_SALT_SIZE = 16; // bytes
  static const PBKDF2_ITERATIONS = 32767;

  static Uint8List encrypt(Uint8List passphrase, Uint8List plaintext, Uint8List aad) {

    // Derive random salt and nonce
    final rnd = getSecureRandom();
    final salt = rnd.nextBytes(PBKDF2_SALT_SIZE);
    final nonce = rnd.nextBytes(ALGORITHM_NONCE_SIZE);

    // PBKDF2 key derivation
    final key = generateKey(salt, passphrase);

    // AES/GCM Encryption
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), ALGORITHM_TAG_SIZE * 8, nonce, aad));
    final ciphertextTag = cipher.process(plaintext);

    return Uint8List.fromList(salt + nonce + ciphertextTag);
  }

  static Uint8List decrypt(Uint8List passphrase, Uint8List encryptedData, Uint8List aad) {

    // Separate salt, nonce and ciphertext|tag
    final salt = encryptedData.sublist(0, PBKDF2_SALT_SIZE);
    final nonce = encryptedData.sublist(PBKDF2_SALT_SIZE, PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
    final ciphertextTag = encryptedData.sublist(PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);

    // PBKDF2 key derivation
    final key = generateKey(salt, passphrase);

    // AES/GCM Decryption
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(key), ALGORITHM_TAG_SIZE * 8, nonce, aad));
    final decrypted = cipher.process(ciphertextTag);

    return decrypted;
  }

  static SecureRandom getSecureRandom() {
    final seed = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    return FortunaRandom()
      ..seed(KeyParameter(Uint8List.fromList(seed)));
  }

  static Uint8List generateKey(Uint8List salt, Uint8List passphrase){
    final derivator = KeyDerivator(PBKDF2_PRF_DIGEST);
    final pbkdf2Params = Pbkdf2Parameters(salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE);
    derivator.init(pbkdf2Params);
    return derivator.process(passphrase);
  }
}
