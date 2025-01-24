//
//  NiftyRSAPrivateKey.swift
//  NiftyRSA
//
//  Created by Lois Di Qual on 5/17/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

public class NiftyRSAPrivateKey: Key {

    /// Reference to the key within the keychain
    public let reference: SecKey

    /// Original data of the private key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public let originalData: Data?

    let tag: String?

    /// Returns a PEM representation of the private key.
    ///
    /// - Returns: Data of the key, PEM-encoded
    /// - Throws: NiftyRSAError
    public func pemString() throws -> String {
        let data = try self.data()
        let pem = NiftyRSA.format(keyData: data, withPemType: "RSA PRIVATE KEY")
        return pem
    }

    /// Creates a private key with a keychain key reference.
    /// This initializer will throw if the provided key reference is not a private RSA key.
    ///
    /// - Parameter reference: Reference to the key within the keychain.
    /// - Throws: NiftyRSAError
    public required init(reference: SecKey) throws {
        guard NiftyRSA.isValidKeyReference(reference, forClass: kSecAttrKeyClassPrivate) else {
            throw NiftyRSAError.notAPrivateKey
        }

        self.reference = reference
        self.tag = nil
        self.originalData = nil
    }

    /// Creates a private key with a RSA public key data.
    ///
    /// - Parameter data: Private key data
    /// - Throws: NiftyRSAError
    required public init(data: Data) throws {
        self.originalData = data
        let tag = UUID().uuidString
        self.tag = tag
        let dataWithoutHeader = try NiftyRSA.stripKeyHeader(keyData: data)
        reference = try NiftyRSA.addKey(dataWithoutHeader, isPublic: false, tag: tag)
    }

    deinit {
        if let tag = tag {
            NiftyRSA.removeKey(tag: tag)
        }
    }
}
