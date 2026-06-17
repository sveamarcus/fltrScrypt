//===----------------------------------------------------------------------===//
//
// This source file is part of the fltrScrypt open source project
//
// Copyright (c) 2022-2026 fltrWallet AG and the fltrScrypt project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
// Shared, Foundation-free helpers for the test suites. Swift Testing does not
// transitively import Foundation, so `hex` / `hex2Bytes` are implemented by hand.

extension StringProtocol {
    /// The ASCII byte values of the string.
    ///
    /// - Precondition: every character is a single ASCII scalar.
    var ascii: [UInt8] {
        self.map { character in
            guard let value = character.asciiValue else {
                preconditionFailure("non-ASCII character \(character) in test string")
            }
            return value
        }
    }
}

extension Sequence where Element == UInt8 {
    /// A lowercase, zero-padded hexadecimal rendering of the bytes.
    var hex: String {
        let digits = Array("0123456789abcdef".utf8)
        var characters: [UInt8] = []
        for byte in self {
            characters.append(digits[Int(byte >> 4)])
            characters.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: characters, as: UTF8.self)
    }
}

extension StringProtocol {
    /// Parses an even-length hexadecimal string into its bytes.
    ///
    /// - Precondition: the string has even length and contains only hex digits.
    var hex2Bytes: [UInt8] {
        precondition(count.isMultiple(of: 2), "hex string must have even length")
        var result: [UInt8] = []
        result.reserveCapacity(count / 2)
        var index = startIndex
        while let next = self.index(index, offsetBy: 2, limitedBy: endIndex), next != index {
            guard let byte = UInt8(self[index..<next], radix: 16) else {
                preconditionFailure("invalid hex digit in \(self)")
            }
            result.append(byte)
            index = next
        }
        return result
    }
}
