//
//  KeyTests.swift
//  NiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest

// Using @testable here so we can call `NiftyRSA.generateRSAKeyPair(sizeInBits:applyUnitTestWorkaround)`
@testable import NiftyRSA

class PublicKeyTests: XCTestCase {

    let bundle = Bundle.module

    func test_initWithReference() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try NiftyRSAPublicKey(data: data)
        let newPublicKey = try? NiftyRSAPublicKey(reference: publicKey.reference)
        XCTAssertNotNil(newPublicKey)
    }

    func test_initWithReference_failsWithPrivateKey() throws {
        guard let path = bundle.path(forResource: "niftyrsa-private", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try NiftyRSAPrivateKey(pemEncoded: str)

        TestUtils.assertThrows(type: NiftyRSAError.notAPublicKey) {
            _ = try NiftyRSAPublicKey(reference: privateKey.reference)
        }
    }

    func test_initWithData() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try? NiftyRSAPublicKey(data: data)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithBase64String() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public-base64", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? NiftyRSAPublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithX509Base64String() throws {
        guard let path = bundle.path(forResource: "base64-X509-public-key", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? NiftyRSAPublicKey(base64EncodedX509Certificate: str)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithBase64StringWhichContainsNewLines() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public-base64-newlines", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? NiftyRSAPublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? NiftyRSAPublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithPEMName() throws {
        let publicKey = try? NiftyRSAPublicKey(pemNamed: "niftyrsa-public", in: bundle)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithDERName() throws {
        let publicKey = try? NiftyRSAPublicKey(pemNamed: "niftyrsa-public", in: bundle)
        XCTAssertNotNil(publicKey)
    }

    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public-headerless", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? NiftyRSAPublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }

    func test_publicKeysFromComplexPEMFileWorksCorrectly() {
        let input = TestUtils.pemKeyString(name: "multiple-keys-testcase")
        let keys = NiftyRSAPublicKey.publicKeys(pemEncoded: input)
        XCTAssertEqual(keys.count, 9)
    }

    func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
        let keys = NiftyRSAPublicKey.publicKeys(pemEncoded: "")
        XCTAssertEqual(keys.count, 0)
    }

    func test_publicKeysFromPrivateKeyPEMFileReturnsEmptyArray() {
        let input = TestUtils.pemKeyString(name: "niftyrsa-private")
        let keys = NiftyRSAPublicKey.publicKeys(pemEncoded: input)
        XCTAssertEqual(keys.count, 0)
    }

    func test_data() throws {

        // With header
        do {
            guard let path = bundle.path(forResource: "niftyrsa-public", ofType: "der") else {
                return XCTFail("file not found in bundle")
            }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let publicKey = try NiftyRSAPublicKey(data: data)

            guard let dataFromKeychain = try? publicKey.data() else {
                return XCTFail("file not found in bundle")
            }

            XCTAssertNotEqual(dataFromKeychain, data)
            XCTAssertEqual(publicKey.originalData, data)
        }

        // Headerless
        do {
            guard let path = bundle.path(forResource: "niftyrsa-public-headerless", ofType: "pem") else {
                return XCTFail("file not found in bundle")
            }
            let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
            let publicKey = try NiftyRSAPublicKey(pemEncoded: str)
            XCTAssertNotNil(publicKey.originalData)
            XCTAssertNotNil(try? publicKey.data())
        }
    }

    func test_pemString() throws {
        let publicKey = try NiftyRSAPublicKey(pemNamed: "niftyrsa-public", in: bundle)
        let pemString = try publicKey.pemString()
        let newPublicKey = try NiftyRSAPublicKey(pemEncoded: pemString)
        XCTAssertNotNil(newPublicKey)
        XCTAssertEqual(try? publicKey.data(), try? newPublicKey.data())
    }

    func test_base64String() throws {
        let publicKey = try NiftyRSAPublicKey(pemNamed: "niftyrsa-public", in: bundle)
        let base64String = try publicKey.base64String()
        let newPublicKey = try NiftyRSAPublicKey(base64Encoded: base64String)
        XCTAssertNotNil(newPublicKey)
        XCTAssertEqual(try? publicKey.data(), try? newPublicKey.data())
    }
}

class PrivateKeyTests: XCTestCase {

    let bundle = Bundle.module

    func test_initWithReference() throws {
        guard let path = bundle.path(forResource: "niftyrsa-private", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try NiftyRSAPrivateKey(pemEncoded: str)

        let newPrivateKey = try? NiftyRSAPrivateKey(reference: privateKey.reference)
        XCTAssertNotNil(newPrivateKey)
    }

    func test_initWithReference_failsWithPublicKey() throws {
        guard let path = bundle.path(forResource: "niftyrsa-public", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try NiftyRSAPublicKey(data: data)

        TestUtils.assertThrows(type: NiftyRSAError.notAPrivateKey) {
            _ = try NiftyRSAPrivateKey(reference: publicKey.reference)
        }
    }

    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "niftyrsa-private", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? NiftyRSAPrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }

    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "niftyrsa-private-headerless", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? NiftyRSAPrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }

    func test_initWithPEMName() throws {
        let message = try? NiftyRSAPrivateKey(pemNamed: "niftyrsa-private", in: Bundle.module)
        XCTAssertNotNil(message)
    }

    func test_initWithDERName() throws {
        let message = try? NiftyRSAPrivateKey(pemNamed: "niftyrsa-private", in: Bundle.module)
        XCTAssertNotNil(message)
    }

    func test_data() throws {
        guard let path = bundle.path(forResource: "niftyrsa-private", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try NiftyRSAPrivateKey(data: data)
        XCTAssertEqual(try? publicKey.data(), data)
    }

    func test_pemString() throws {
        let privateKey = try NiftyRSAPrivateKey(pemNamed: "niftyrsa-private", in: bundle)
        let pemString = try privateKey.pemString()
        let newPrivateKey = try NiftyRSAPrivateKey(pemEncoded: pemString)
        XCTAssertNotNil(newPrivateKey)
        XCTAssertEqual(try? privateKey.data(), try? newPrivateKey.data())
    }

    func test_base64String() throws {
        let privateKey = try NiftyRSAPrivateKey(pemNamed: "niftyrsa-private", in: bundle)
        let base64String = try privateKey.base64String()
        let newPrivateKey = try NiftyRSAPrivateKey(base64Encoded: base64String)
        XCTAssertEqual(try? privateKey.data(), try? newPrivateKey.data())
    }

    func test_headerAndOctetString() throws {
        _ = try NiftyRSAPrivateKey(pemNamed: "niftyrsa-private-header-octetstring", in: bundle)
    }

    func test_generateKeyPair() throws {
        let keyPair = try NiftyRSA.generateRSAKeyPair(sizeInBits: 2048, applyUnitTestWorkaround: true)

        let algorithm: Algorithm = .rsaEncryptionOAEPSHA512
        guard SecKeyIsAlgorithmSupported(keyPair.privateKey.reference, .decrypt, algorithm) else {
            XCTFail("Key cannot be used for decryption")
            return
        }

        guard SecKeyIsAlgorithmSupported(keyPair.publicKey.reference, .encrypt, algorithm) else {
            XCTFail("Key cannot be used for encryption")
            return
        }

        let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str)

        let encrypted = try clearMessage.encrypted(with: keyPair.publicKey)
        let decrypted = try encrypted.decrypted(with: keyPair.privateKey)

        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
}
