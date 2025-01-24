NiftyRSA
=========

**Public key RSA encryption in Swift.**

Renamed fork of the SwiftyRSA (https://github.com/TakeScoop/SwiftyRSA) project which is used in the [Scoop](https://www.takescoop.com/) [iOS app](https://itunes.apple.com/us/app/scoop-easy-custom-carpooling/id997978145?mt=8) to encrypt driver license numbers before submitting them to Checkr through theire API.

Quick Start
-----------

### Encrypt with a public key

```swift
do {
    let publicKey = try NiftyRSAPublicKey(pemNamed: "public")

    let str = "Clear String"
    let clear = try ClearMessage(string: str, using: .utf8)
    let encrypted = try clear.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)

    let data = encencrypted.data
    print(data)
    
    let base64String = encrypted.base64String
    print(base64String)
} catch {
    print(error)
}
```

### Decrypt with a private key

```swift
let privateKey = try NiftyRSAPrivateKey(pemNamed: "private")
let encrypted = try EncryptedMessage(base64Encoded: "AAA===")
let clear = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)

// Then you can use:
let data = clear.data
let base64String = clear.base64String
let string = clear.string(using: .utf8)
```


Advanced Usage
--------------

### Create a public/private key representation

#### With a DER file

```swift
let publicKey = try NiftyRSAPublicKey(derNamed: "public")
let privateKey = try NiftyRSAPrivateKey(derNamed: "private")
```

#### With a PEM file

```swift
let publicKey = try NiftyRSAPublicKey(pemNamed: "public")
let privateKey = try NiftyRSAPrivateKey(pemNamed: "private")
```

#### With a PEM string

```swift
let publicKey = try NiftyRSAPublicKey(pemEncoded: str)
let privateKey = try NiftyRSAPrivateKey(pemEncoded: str)
```

#### With a Base64 string

```swift
let publicKey = try NiftyRSAPublicKey(base64Encoded: base64String)
let privateKey = try NiftyRSAPrivateKey(base64Encoded: base64String)
```

#### With data

```swift
let publicKey = try NiftyRSAPublicKey(data: data)
let privateKey = try NiftyRSAPrivateKey(data: data)
```

#### With a SecKey

```swift
let publicKey = try NiftyRSAPublicKey(reference: secKey)
let privateKey = try NiftyRSAPrivateKey(reference: secKey)
```

### Encrypt with a public key

```swift
let str = "Clear Text"
let clear = try ClearMessage(string: str, using: .utf8)
let encrypted = try clear.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)

let data = encrypted.data
let base64String = encrypted.base64Encoded
```

### Decrypt with a private key

```swift
let encrypted = try EncryptedMessage(base64Encoded: base64String)
let clear = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)

let data = clear.data
let base64String = clear.base64Encoded
let string = try clear.string(using: .utf8)
```

### Sign with a private key

NiftyRSA can sign data with a private key. NiftyRSA will calculate a SHA digest of the supplied `String`/`Data` and use this to generate the digital signature.

```swift
let clear = try ClearMessage(string: "Clear Text", using: .utf8)
let signature = clear.signed(with: privateKey, digestType: .sha1)

let data = signature.data
let base64String = signature.base64String
```

### Verify with a public key

NiftyRSA can verify digital signatures with a public key. NiftyRSA will calculate a digest of the supplied `String`/`Data` and use this to verify the digital signature.

```swift
let signature = try Signature(base64Encoded: "AAA===")
let isSuccessful = try clear.verify(with: publicKey, signature: signature, digestType: .sha1)
```

### Create a public/private RSA key pair

```swift
let keyPair = NiftyRSA.generateRSAKeyPair(sizeInBits: 2048)
let privateKey = keyPair.privateKey
let publicKey = keyPair.publicKey
```

### Export a key or access its content

```swift
let pem = try key.pemString()
let base64 = try key.base64String()
let data = try key.data()
let reference = key.reference
let originalData = key.originalData
```

### Use X.509 certificate 
NiftyRSA supports X.509 certificate for public keys. NiftyRSA can add the X.509 header to a headerless public key, or on the contrary  strip it to get a key without a header.
#### Add an X.509 header to a public key 
```swift
let publicKey = NiftyRSAPublicKey(data: data)
let publicKeyData = try publicKey.data()
let publicKey_with_X509_header = try NiftyRSA.prependX509KeyHeader(keyData: publicKeyData)
```
#### Strip the X.509 header from a public key 
```swift
let publicKey_headerLess: Data = try NiftyRSA.stripKeyHeader(keyData: publicKey_with_X509_header)
```

**Warning** : Storing (with NiftyRSA's methods) or creating a ```NiftyRSAPublicKey``` instance will automatically strip the header from the key. For more info, see *Under the hood* above.

Create public and private RSA keys
----------------------------------

Use `ssh-keygen` to generate a PEM public key and a PEM private key. NiftyRSA also supports DER public keys.

```
$ ssh-keygen -t rsa -m PEM -f ~/mykey -N ''
$ cat ~/mykey > ~/private.pem
$ ssh-keygen -f ~/mykey.pub -e -m pem > ~/public.pem
```

Your keys are now in `~/public.pem` and `~/private.pem`. Don't forget to move `~/mykey` and `~/mykey.pub` to a secure place.

Under the hood
--------------

To enable using public/private RSA keys on iOS, NiftyRSA uses a couple techniques like X.509 header stripping so that the keychain accepts them.

<details>
	<summary>Click here for more details</summary>

When encrypting using a public key:

 - If the key is in PEM format, get rid of its meta data and convert it to Data
 - Strip the public key X.509 header, otherwise the keychain won't accept it
 - Add the public key to the keychain, with a random tag
 - Get a reference on the key using the key tag
 - Use `SecKeyEncrypt` to encrypt a `ClearMessage` using the key reference and the message data.
 - Store the resulting encrypted data to an `EncryptedMessage`
 - When the key gets deallocated, delete the public key from the keychain using its tag

When decrypting using a private key:

 - Get rid of PEM meta data and convert to Data
 - Add the private key to the app keychain, with a random tag
 - Get a reference on the key using the key tag
 - Use `SecKeyDecrypt` to decrypt an `EncryptedMessage` using the key reference and the encrypted message data
 - Store the resulting decrypted data to a `ClearMessage`
 - Delete private key from keychain using tag
</details>

Inspired from
-------------

 - <http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/>
 - <https://github.com/lancy/RSADemo>
 - <https://github.com/btnguyen2k/swift-rsautils>

License
-------

This project is copyrighted under the MIT license. Complete license can be found here: <https://github.com/unibas-medfak/NiftyRSA/blob/master/LICENSE>
