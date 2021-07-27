# Dart-implementation-of-AES-GCM-and-PBKDF2-using-PointyCastle

The code is a possible implementation of AES in GCM mode and PBKDF2 as key derivation function using the libraries: 

  - pointycastle: ^3.1.3
  - convert: ^3.0.1

The parameters have to be adapted for the target system (especially `PBKDF2_ITERATIONS` has to be chosen as large as possible with acceptable performance). 

Note that this code is not maintained.

With the parameters used, the implementation is compatible with the cross-platform library [_SecureCompatibleEncryptionExamples_][1], which also provides implementations for Kotlin and JavaScript, among others. 



[1]: https://github.com/luke-park/SecureCompatibleEncryptionExamples 

