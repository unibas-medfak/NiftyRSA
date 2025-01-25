//
//  EncryptDecryptTests.swift
//  NiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import NiftyRSA
import XCTest

class EncryptDecryptTests: XCTestCase {

    /// PKCS#1 v1.5 with 1024 bit RSA key can encrypt up to 117 bytes.
    let byteLimitForPKCS1 = 117
    /// PKCS#1 v2.1 with 1024 bit RSA key can encrypt up to 86 bytes for SHA-1.
    let byteLimitForOAEP = 86

    let publicKey = try! TestUtils.publicKey(name: "niftyrsa-public")
    let privateKey = try! TestUtils.privateKey(name: "niftyrsa-private")

    func test_simple() throws {
        let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str)

        let encrypted = try clearMessage.encrypted(with: publicKey)
        let decrypted = try encrypted.decrypted(with: privateKey)

        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }

    func test_longString() throws {
        let str = [String](repeating: "a", count: 99).joined(separator: "")
        let clearMessage = try ClearMessage(string: str)

        let encrypted = try clearMessage.encrypted(with: publicKey)
        let decrypted = try encrypted.decrypted(with: privateKey)

        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }

    func test_randomBytes() throws {
        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)

        let encrypted = try clearMessage.encrypted(with: publicKey)
        let decrypted = try encrypted.decrypted(with: privateKey)

        XCTAssertEqual(decrypted.data, data)
    }

    func test_noPadding() throws {
        let data = TestUtils.randomData(count: 128)
        let clearMessage = ClearMessage(data: data)
        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionRaw)

        let clearMessage2 = ClearMessage(data: encrypted.data)
        let encrypted2 = try clearMessage2.encrypted(with: publicKey, algorithm: .rsaEncryptionRaw)

        XCTAssertEqual(data.count, encrypted.data.count)
        XCTAssertEqual(data.count, encrypted2.data.count)

        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionRaw)

        XCTAssertEqual(decrypted.data, data)
    }

    func test_OAEP() throws {
        let data = TestUtils.randomData(count: byteLimitForOAEP)
        let clearMessage = ClearMessage(data: data)

        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionOAEPSHA1)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionOAEPSHA1)

        XCTAssertEqual(decrypted.data, data)
    }

    func test_keyReferences() throws {
        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)

        let newPublicKey = try NiftyRSAPublicKey(reference: publicKey.reference)
        let newPrivateKey = try NiftyRSAPrivateKey(reference: privateKey.reference)

        // Encrypt with old public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey)
            let decrypted = try encrypted.decrypted(with: privateKey)
            XCTAssertEqual(decrypted.data, data)
        }

        // Encrypt with old public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey)
            let decrypted = try encrypted.decrypted(with: newPrivateKey)
            XCTAssertEqual(decrypted.data, data)
        }

        // Encrypt with new public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey)
            let decrypted = try encrypted.decrypted(with: privateKey)
            XCTAssertEqual(decrypted.data, data)
        }

        // Encrypt with new public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey)
            let decrypted = try encrypted.decrypted(with: newPrivateKey)
            XCTAssertEqual(decrypted.data, data)
        }
    }

    func test_keyData() throws {
        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)

        let newPublicKey = try NiftyRSAPublicKey(data: try publicKey.data())
        let newPrivateKey = try NiftyRSAPrivateKey(data: try privateKey.data())

        // Encrypt with old public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey)
            let decrypted = try encrypted.decrypted(with: privateKey)
            XCTAssertEqual(decrypted.data, data)
        }

        // Encrypt with old public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey)
            let decrypted = try encrypted.decrypted(with: newPrivateKey)
            XCTAssertEqual(decrypted.data, data)
        }

        // Encrypt with new public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey)
            let decrypted = try encrypted.decrypted(with: privateKey)
            XCTAssertEqual(decrypted.data, data)
        }

        // Encrypt with new public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey)
            let decrypted = try encrypted.decrypted(with: newPrivateKey)
            XCTAssertEqual(decrypted.data, data)
        }
    }
}
