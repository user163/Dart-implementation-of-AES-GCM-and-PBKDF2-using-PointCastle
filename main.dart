import 'package:flutter/material.dart';

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

  // -------------------------------------------
  runApp(MyApp());
}


class MyApp extends StatelessWidget {
  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // Try running your application with "flutter run". You'll see the
        // application has a blue toolbar. Then, without quitting the app, try
        // changing the primarySwatch below to Colors.green and then invoke
        // "hot reload" (press "r" in the console where you ran "flutter run",
        // or simply save your changes to "hot reload" in a Flutter IDE).
        // Notice that the counter didn't reset back to zero; the application
        // is not restarted.
        primarySwatch: Colors.blue,
      ),
      home: MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
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
    Random rnd = Random.secure(); // https://github.com/dart-lang/sdk/issues/1746
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

    // Generate nonce and salt
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

  // --------------------------------------------------------------------------------------------------------------------------------
  // https://github.com/bcgit/pc-dart/blob/master/test/modes/gcm_test.dart
  static Uint8List encrypt_withfortuna(Uint8List passphrase, Uint8List plaintext) {

    // Generate nonce and salt
    SecureRandom secureRandom = getFortunaRandom();
    Uint8List salt = secureRandom.nextBytes(PBKDF2_SALT_SIZE);
    Uint8List nonce = secureRandom.nextBytes(ALGORITHM_NONCE_SIZE);
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

  static SecureRandom getFortunaRandom() {
    FortunaRandom secureRandom = FortunaRandom(); // https://pub.dev/documentation/pointycastle/latest/impl.secure_random.fortuna_random/FortunaRandom-class.html
                                                  // https://github.com/PointyCastle/pointycastle/blob/master/lib/random/fortuna_random.dart

    Random seedSource = Random.secure();
    List<int> seeds = <int>[];
    for (int i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    return secureRandom;
  }
}

class MyHomePage extends StatefulWidget {
  MyHomePage({Key key, this.title}) : super(key: key);

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      _counter++;
    });
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Invoke "debug painting" (press "p" in the console, choose the
          // "Toggle Debug Paint" action from the Flutter Inspector in Android
          // Studio, or the "Toggle Debug Paint" command in Visual Studio Code)
          // to see the wireframe for each widget.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headline4,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
