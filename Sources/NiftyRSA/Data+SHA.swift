//
//  Data+SHA.swift
//
//
//  Created by Joanna Bednarz on 02/10/2020.
//

import CommonCrypto
import Foundation

extension Data {

    func niftyRSASHA1() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            _ = CC_SHA1(buffer.baseAddress, CC_LONG(count), &digest)
        }
        return Data(digest)
    }

    func niftyRSASHA224() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            _ = CC_SHA224(buffer.baseAddress, CC_LONG(count), &digest)
        }
        return Data(digest)
    }

    func niftyRSASHA256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(count), &digest)
        }
        return Data(digest)
    }

    func niftyRSASHA384() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            _ = CC_SHA384(buffer.baseAddress, CC_LONG(count), &digest)
        }
        return Data(digest)
    }

    func niftyRSASHA512() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            _ = CC_SHA512(buffer.baseAddress, CC_LONG(count), &digest)
        }
        return Data(digest)
    }
}
