//
//  TestUtils.swift
//  NiftyRSA
//
//  Created by Loïs Di Qual on 4/1/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation
import NiftyRSA
import XCTest

struct TestError: Error {
    let description: String
}

public class TestUtils {

    static let bundle = Bundle.module

    static public func pemKeyString(name: String) -> String {
        let pubPath = bundle.path(forResource: name, ofType: "pem")!
        return (try! NSString(contentsOfFile: pubPath, encoding: String.Encoding.utf8.rawValue)) as String
    }

    static public func derKeyData(name: String) -> Data {
        let pubPath = bundle.path(forResource: name, ofType: "der")!
        return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
    }

    static public func publicKey(name: String) throws -> NiftyRSAPublicKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        return try NiftyRSAPublicKey(pemEncoded: pemString)
    }

    static public func privateKey(name: String) throws -> NiftyRSAPrivateKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        return try NiftyRSAPrivateKey(pemEncoded: pemString)
    }

    static public func randomData(count: Int) -> Data {
        var randomBytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &randomBytes)
        if status != errSecSuccess {
            XCTFail("Couldn't create random data")
        }
        return Data(randomBytes)
    }

    static func assertThrows(type: NiftyRSAError, file: StaticString = #filePath, line: UInt = #line, block: () throws -> Void) {
        do {
            try block()
            XCTFail("The line above should fail", file: file, line: line)
        }
        catch {
            guard let niftyRsaError = error as? NiftyRSAError else {
                return XCTFail("Error is not a NiftyRSAError", file: file, line: line)
            }
            XCTAssertEqual(niftyRsaError, type, file: file, line: line)
        }
    }
}

extension NiftyRSAError: Equatable {
    public static func == (lhs: NiftyRSAError, rhs: NiftyRSAError) -> Bool {
        switch (lhs, rhs) {
        case (.pemDoesNotContainKey, .pemDoesNotContainKey),
            (.keyRepresentationFailed, .keyRepresentationFailed),
            (.keyAddFailed, .keyAddFailed),
            (.keyCopyFailed, .keyCopyFailed),
            (.tagEncodingFailed, .tagEncodingFailed),
            (.asn1ParsingFailed, .asn1ParsingFailed),
            (.invalidAsn1RootNode, .invalidAsn1RootNode),
            (.invalidAsn1Structure, .invalidAsn1Structure),
            (.invalidBase64String, .invalidBase64String),
            (.decryptFailed, .decryptFailed),
            (.encryptFailed, .encryptFailed),
            (.stringToDataConversionFailed, .stringToDataConversionFailed),
            (.dataToStringConversionFailed, .dataToStringConversionFailed),
            (.invalidDigestSize, .invalidDigestSize),
            (.signatureCreateFailed, .signatureCreateFailed),
            (.signatureVerifyFailed, .signatureVerifyFailed),
            (.pemFileNotFound, .pemFileNotFound),
            (.derFileNotFound, .derFileNotFound),
            (.notAPublicKey, .notAPublicKey),
            (.notAPrivateKey, .notAPrivateKey):
            return true
        default:
            return false
        }
    }
}
