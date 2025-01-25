//
//  NiftyRSAErrorTests.swift
//  NiftyRSA
//
//  Created by Leonir on 27/10/21.
//  Copyright © 2021 Scoop. All rights reserved.
//

import XCTest

@testable import NiftyRSA

final class NiftyRSAErrorTests: XCTestCase {

    private enum DummyError: Error, LocalizedError {
        case dummyFailed(Error)

        var errorDescription: String? {
            switch self {
            case .dummyFailed:
                return "Dummy Failed"
            }
        }

        var failureReason: String? {
            switch self {
            case .dummyFailed(let error):
                return error.localizedDescription
            }
        }
    }

    func test_getLocalizedDescription_whenNiftyRSAErrorIsTypedWithErrorGeneric() {
        let sut: DummyError = .dummyFailed(NiftyRSAError.notAPublicKey)
        XCTAssertEqual(sut.localizedDescription, "Dummy Failed")
        XCTAssertEqual(sut.failureReason, "Provided key is not a valid RSA public key")
    }

    func test_allcases_shouldVerifyLocalizedDescriptions() {
        mockCases().forEach {
            switch $0 {
            case .pemDoesNotContainKey:
                XCTAssertEqual($0.localizedDescription, "Couldn't get data from PEM key: no data available after stripping headers")
            case .keyRepresentationFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't retrieve key data from the keychain: CFError \(String(describing: error))")
            case .keyGenerationFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't generate key pair: CFError: \(String(describing: error))")
            case .keyCreateFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't create key reference from key data: CFError \(String(describing: error))")
            case .keyAddFailed(let status):
                XCTAssertEqual($0.localizedDescription, "Couldn't retrieve key data from the keychain: OSStatus \(status)")
            case .keyCopyFailed(let status):
                XCTAssertEqual($0.localizedDescription, "Couldn't copy and retrieve key reference from the keychain: OSStatus \(status)")
            case .tagEncodingFailed:
                XCTAssertEqual($0.localizedDescription, "Couldn't create tag data for key")
            case .asn1ParsingFailed:
                XCTAssertEqual($0.localizedDescription, "Couldn't parse the ASN1 key data. Please file a bug at https://github.com/unibas-medfak/NiftyRSA/issues")
            case .invalidAsn1RootNode:
                XCTAssertEqual($0.localizedDescription, "Couldn't parse the provided key because its root ASN1 node is not a sequence. The key is probably corrupt")
            case .invalidAsn1Structure:
                XCTAssertEqual($0.localizedDescription, "Couldn't parse the provided key because it has an unexpected ASN1 structure")
            case .invalidBase64String:
                XCTAssertEqual($0.localizedDescription, "The provided string is not a valid Base64 string")
            case .decryptFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't decrypt data: CFError \(String(describing: error))")
            case .encryptFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't encrypt data: CFError \(String(describing: error))")
            case .stringToDataConversionFailed:
                XCTAssertEqual($0.localizedDescription, "Couldn't convert string to data using specified encoding")
            case .dataToStringConversionFailed:
                XCTAssertEqual($0.localizedDescription, "Couldn't convert data to string representation")
            case .invalidDigestSize(let digestSize, let maxChunkSize):
                XCTAssertEqual($0.localizedDescription, "Provided digest type produces a size (\(digestSize)) that is bigger than the maximum chunk size \(maxChunkSize) of the RSA key")
            case .signatureCreateFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't sign provided data: CFError \(String(describing: error))")
            case .signatureVerifyFailed(let error):
                XCTAssertEqual($0.localizedDescription, "Couldn't verify signature of the provided data: CFError \(String(describing: error))")
            case .pemFileNotFound(let name):
                XCTAssertEqual($0.localizedDescription, "Couldn't find a PEM file named '\(name)'")
            case .derFileNotFound(let name):
                XCTAssertEqual($0.localizedDescription, "Couldn't find a DER file named '\(name)'")
            case .notAPublicKey:
                XCTAssertEqual($0.localizedDescription, "Provided key is not a valid RSA public key")
            case .notAPrivateKey:
                XCTAssertEqual($0.localizedDescription, "Provided key is not a valid RSA pivate key")
            case .x509CertificateFailed:
                XCTAssertEqual($0.localizedDescription, "Couldn't prepend the provided key because it has an unexpected structure")
            }
        }
    }
}

extension NiftyRSAErrorTests {
    private func mockCases() -> [NiftyRSAError] {
        return [
            .pemDoesNotContainKey,
            .keyRepresentationFailed(error: nil),
            .keyGenerationFailed(error: nil),
            .keyCreateFailed(error: nil),
            .keyAddFailed(status: errSecSuccess),
            .keyCopyFailed(status: errSecSuccess),
            .tagEncodingFailed,
            .asn1ParsingFailed,
            .invalidAsn1RootNode,
            .invalidAsn1Structure,
            .invalidBase64String,
            .decryptFailed(error: nil),
            .encryptFailed(error: nil),
            .stringToDataConversionFailed,
            .dataToStringConversionFailed,
            .invalidDigestSize(digestSize: 0, maxChunkSize: 0),
            .signatureCreateFailed(error: nil),
            .signatureVerifyFailed(error: nil),
            .pemFileNotFound(name: "dummy"),
            .derFileNotFound(name: "dummy"),
            .notAPublicKey,
            .notAPrivateKey,
            .x509CertificateFailed,
        ]
    }
}
