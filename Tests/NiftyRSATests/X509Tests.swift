//
//  X509Tests.swift
//  NiftyRSA iOS
//
//  Created by Stchepinsky Nathan on 23/07/2021.
//  Copyright © 2021 Scoop. All rights reserved.
//

import Foundation
import XCTest

// Using @testable here so we can call `NiftyRSA.stripKeyHeader(keyData: Data)`
@testable import NiftyRSA

class X509CertificateTests: XCTestCase {

    /// PKCS#1 v1.5 with 1024 bit RSA key can encrypt up to 117 bytes.
    let byteLimitForPKCS1 = 117

    let publicKey = try! TestUtils.publicKey(name: "niftyrsa-public")
    let privateKey = try! TestUtils.privateKey(name: "niftyrsa-private")
    let bundle = Bundle.module

    /// Verify the ASN1 sruc with the ASN1 parser (private key)
    func testX509CertificateValidityPrivateKey() throws {
        guard let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let privateKeyX509: Data = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)

        XCTAssertTrue(try privateKeyX509.hasX509Header())
    }

    /// Test the function in charge of verifying if a key is headerless or not
    func testHeaderlessKeyVerificationFunc() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        // Correct key
        XCTAssertTrue(try publicKeyData.isAnHeaderlessKey())
        XCTAssertTrue(try privateKeyData.isAnHeaderlessKey())

        // Example of incorrect key (here with a X509 header)
        let publicKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: publicKeyData)
        let privateKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)
        XCTAssertFalse(try publicKeyX509.isAnHeaderlessKey())
        XCTAssertFalse(try privateKeyX509.isAnHeaderlessKey())
    }

    /// Verify that the header added corresponds to the X509 key
    func testX509HeaderVerificationPublicKey() throws {
        // Generated on https://www.devglan.com/online-tools/rsa-encryption-decryption which uses X.509 certificate for public key
        guard let path = bundle.path(forResource: "niftyrsa-public-base64-X509-format", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        if let publicKey = try? NiftyRSAPublicKey(base64Encoded: str) {  // Creating a public key strip the X509 header
            let publicKey509 = try NiftyRSA.prependX509KeyHeader(keyData: publicKey.data())
            let publicKey509Base64 = publicKey509.base64EncodedString()
            XCTAssertEqual(publicKey509Base64, str)
        }
        else {
            return XCTFail("Key isn't valid")
        }
    }

    /// Test if the key's format is correct with the hasX509Header func
    func testX509KeyHeader() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let publicKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: publicKeyData)
        let privateKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)

        XCTAssertTrue(try publicKeyX509.hasX509Header())
        XCTAssertTrue(try privateKeyX509.hasX509Header())
    }

    /// Verify if the X509 header can be stripped
    func testStripX509HeaderPrivateKey() throws {
        guard let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let privateKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)

        let privateKeyStripped = try NiftyRSA.stripKeyHeader(keyData: privateKeyX509)
        XCTAssertEqual(privateKeyData, privateKeyStripped)
    }

    /// Test if a key with X509 header can encrypt and decrypt a given simple message
    func testEncryptionDecryptionSimple() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let privateKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)
        let publicKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: publicKeyData)

        let clear = "Hello world !"
        let clearMessage = try ClearMessage(string: clear, using: .utf8)

        let encrypted = try clearMessage.encrypted(with: NiftyRSAPublicKey(data: publicKeyX509), algorithm: .rsaEncryptionPKCS1)
        let decrypted = try encrypted.decrypted(with: NiftyRSAPrivateKey(data: privateKeyX509), algorithm: .rsaEncryptionPKCS1)

        XCTAssertEqual(try? decrypted.string(encoding: .utf8), clear)
    }

    /// Test if a key with X509 header can encrypt and decrypt a given long message
    func testEncryptionDecryptionLong() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let privateKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)
        let publicKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: publicKeyData)

        let clear = [String](repeating: "a", count: 99).joined(separator: "")
        let clearMessage = try ClearMessage(string: clear, using: .utf8)

        let encrypted = try clearMessage.encrypted(with: NiftyRSAPublicKey(data: publicKeyX509), algorithm: .rsaEncryptionPKCS1)
        let decrypted = try encrypted.decrypted(with: NiftyRSAPrivateKey(data: privateKeyX509), algorithm: .rsaEncryptionPKCS1)

        XCTAssertEqual(try? decrypted.string(encoding: .utf8), clear)
    }

    /// Test if a key with X509 header can encrypt and decrypt a given random message
    func testEncryptionDecryptionRandomBytes() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let privateKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: privateKeyData)
        let publicKeyX509 = try NiftyRSA.prependX509KeyHeader(keyData: publicKeyData)

        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)

        let encrypted = try clearMessage.encrypted(with: NiftyRSAPublicKey(data: publicKeyX509), algorithm: .rsaEncryptionPKCS1)
        let decrypted = try encrypted.decrypted(with: NiftyRSAPrivateKey(data: privateKeyX509), algorithm: .rsaEncryptionPKCS1)

        XCTAssertEqual(decrypted.data, data)
    }
}
