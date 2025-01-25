//
//  ClearMessage.swift
//  NiftyRSA
//
//  Created by Lois Di Qual on 5/18/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

public class ClearMessage: Message {

    /// Data of the message
    public let data: Data

    /// Creates a clear message with data.
    ///
    /// - Parameter data: Data of the clear message
    public required init(data: Data) {
        self.data = data
    }

    /// Creates a clear message from a string, with the specified encoding.
    ///
    /// - Parameters:
    ///   - string: String value of the clear message
    ///   - encoding: Encoding to use to generate the clear data
    /// - Throws: NiftyRSAError
    public convenience init(string: String, using encoding: String.Encoding = .utf8) throws {
        guard let data = string.data(using: encoding) else {
            throw NiftyRSAError.stringToDataConversionFailed
        }
        self.init(data: data)
    }

    /// Returns the string representation of the clear message using the specified
    /// string encoding.
    ///
    /// - Parameter encoding: Encoding to use during the string conversion
    /// - Returns: String representation of the clear message
    /// - Throws: NiftyRSAError
    public func string(encoding: String.Encoding = .utf8) throws -> String {
        guard let str = String(data: data, encoding: encoding) else {
            throw NiftyRSAError.dataToStringConversionFailed
        }
        return str
    }

    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - key: Public key to encrypt the clear message with
    ///   - algorithm: Algorithm to use during the encryption
    /// - Returns: Encrypted message
    /// - Throws: NiftyRSAError
    public func encrypted(with key: NiftyRSAPublicKey, algorithm: Algorithm = .rsaEncryptionPKCS1) throws -> EncryptedMessage {
        var error: Unmanaged<CFError>?
        let encryptedData = SecKeyCreateEncryptedData(key.reference, algorithm, data as CFData, &error)
        guard let encryptedData else {
            throw NiftyRSAError.encryptFailed(error: error?.takeRetainedValue())
        }

        return EncryptedMessage(data: encryptedData as Data)
    }

    /// Signs a clear message using a private key.
    /// The clear message will first be hashed using the specified digest type, then signed
    /// using the provided private key.
    ///
    /// - Parameters:
    ///   - key: Private key to sign the clear message with
    ///   - digestType: Digest
    /// - Returns: Signature of the clear message after signing it with the specified digest type.
    /// - Throws: NiftyRSAError
    public func signed(with key: NiftyRSAPrivateKey, digestType: Signature.DigestType) throws -> Signature {
        var error: Unmanaged<CFError>?
        let signatureData = SecKeyCreateSignature(key.reference, digestType.algorithm, digest(digestType: digestType) as CFData, &error)
        guard let signatureData else {
            throw NiftyRSAError.signatureCreateFailed(error: error?.takeRetainedValue())
        }

        return Signature(data: signatureData as Data)
    }

    /// Verifies the signature of a clear message.
    ///
    /// - Parameters:
    ///   - key: Public key to verify the signature with
    ///   - signature: Signature to verify
    ///   - digestType: Digest type used for the signature
    /// - Returns: Result of the verification
    /// - Throws: NiftyRSAError
    public func verify(with key: NiftyRSAPublicKey, signature: Signature, digestType: Signature.DigestType) throws -> Bool {
        var error: Unmanaged<CFError>?
        guard error == nil else {
            throw NiftyRSAError.signatureVerifyFailed(error: error?.takeRetainedValue())
        }
        return SecKeyVerifySignature(key.reference, digestType.algorithm, digest(digestType: digestType) as CFData, signature.data as CFData, &error)
    }

    func digest(digestType: Signature.DigestType) -> Data {

        let digest: Data

        switch digestType {
        case .sha1:
            digest = data.niftyRSASHA1()
        case .sha224:
            digest = data.niftyRSASHA224()
        case .sha256:
            digest = data.niftyRSASHA256()
        case .sha384:
            digest = data.niftyRSASHA384()
        case .sha512:
            digest = data.niftyRSASHA512()
        }

        return digest
    }
}
