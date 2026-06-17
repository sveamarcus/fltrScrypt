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
import Clibscrypt

/// The error thrown when libscrypt rejects its inputs or fails internally.
///
/// libscrypt reports a single `-1` for every failure mode — an `N` that is not a
/// power of two greater than one, a zero `r` or `p`, an `r * p` product of `2³⁰`
/// or more, an output length the algorithm cannot satisfy, or an allocation
/// failure — so this error is deliberately opaque.
public struct ScryptInternalError: Error, Sendable, Hashable {
    @usableFromInline init() {}
}

/// The cost and output-size parameters of an scrypt key derivation.
public struct ScryptParameters: Sendable, Hashable {
    /// CPU/memory cost. Must be a power of two greater than one.
    public let N: UInt64
    /// Block-size factor.
    public let r: UInt32
    /// Parallelisation factor.
    public let p: UInt32
    /// Desired output length, in bytes.
    public let length: Int

    @usableFromInline
    init(N: UInt64, r: UInt32, p: UInt32, length: Int) {
        self.N = N
        self.r = r
        self.p = p
        self.length = length
    }

    /// Creates a parameter set from the standard scrypt cost factors.
    @inlinable
    public static func N(_ N: UInt64, r: UInt32, p: UInt32, length: Int) -> Self {
        ScryptParameters(N: N, r: r, p: p, length: length)
    }
}

extension ScryptParameters {
    /// BIP-38 non-EC-multiplied key derivation (`N = 16384, r = 8, p = 8`, 64-byte output).
    public static let bip38nonmul: Self = .N(16384, r: 8, p: 8, length: 64)
    /// BIP-38 EC-multiplied intermediate-passphrase derivation (32-byte output).
    public static let bip38intermediate: Self = .N(16384, r: 8, p: 8, length: 32)
    /// BIP-38 EC-multiplied factor-`b` derivation (`N = 1024, r = 1, p = 1`, 64-byte output).
    public static let bip38mul: Self = .N(1024, r: 1, p: 1, length: 64)
}

/// Invokes `body` with a guaranteed non-`nil` pointer to the bytes of `bytes`.
///
/// `Array.withUnsafeBufferPointer` is documented to yield a `nil` base address
/// for an empty array — and does so on some platforms (notably Linux) even where
/// Apple platforms return a non-`nil` pointer. Forwarding that `nil` to
/// libscrypt would force-unwrap-trap on the Swift side and risk
/// `memcpy(NULL, …, 0)` undefined behaviour on the C side. This helper
/// substitutes a valid, never-dereferenced placeholder for the empty case, so an
/// empty password or salt is handled identically and safely on every platform.
@inlinable
func withBytePointer<Result>(
    _ bytes: [UInt8],
    _ body: (UnsafePointer<UInt8>) -> Result
) -> Result {
    bytes.withUnsafeBufferPointer { buffer in
        if let base = buffer.baseAddress {
            return body(base)
        }
        // Empty array with a `nil` base address: hand the C routine a valid,
        // non-`nil` pointer paired with a length of zero, which it never reads.
        var placeholder: UInt8 = 0
        return withUnsafePointer(to: &placeholder) { body($0) }
    }
}

/// Invokes `body` with a guaranteed non-`nil` pointer to the start of `buffer`.
///
/// The mutable counterpart of ``withBytePointer(_:_:)``. A zero-capacity buffer's
/// base address may be `nil`; passing that to libscrypt's `buf` output parameter
/// is undefined behaviour even though it is never written when the requested
/// length is zero. This substitutes a valid, non-`nil` placeholder for that case.
@inlinable
func withMutableBytePointer<Result>(
    _ buffer: UnsafeMutableBufferPointer<UInt8>,
    _ body: (UnsafeMutablePointer<UInt8>) -> Result
) -> Result {
    if let base = buffer.baseAddress {
        return body(base)
    }
    var placeholder: UInt8 = 0
    return withUnsafeMutablePointer(to: &placeholder) { body($0) }
}

/// Derives a key from `password` and `salt` using scrypt (Percival, RFC 7914).
///
/// - Parameters:
///   - password: The password bytes. May be empty.
///   - salt: The salt bytes. May be empty.
///   - parameters: The cost factors and desired output length.
/// - Returns: The derived key, exactly `parameters.length` bytes long.
/// - Throws: ``ScryptInternalError`` if `parameters` is rejected — a negative
///   length, a non power-of-two `N`, a zero `r`/`p`, an `r * p` of `2³⁰` or more,
///   or any other length the algorithm cannot produce.
@inlinable
public func scrypt(
    password: [UInt8],
    salt: [UInt8],
    parameters: ScryptParameters
) throws(ScryptInternalError) -> [UInt8] {
    // A negative length is outside scrypt's domain. Throw rather than trap so the
    // contract (and `try?` consumers such as fltrBIP38) hold in every build mode.
    guard parameters.length >= 0 else { throw ScryptInternalError() }

    // libscrypt only writes `buf` on the success path, so a failure leaves the
    // buffer uninitialised: report zero initialised elements and throw.
    var status: Int32 = -1
    let derived = [UInt8](unsafeUninitializedCapacity: parameters.length) { buffer, setSizeTo in
        status = withBytePointer(password) { passwordPointer in
            withBytePointer(salt) { saltPointer in
                withMutableBytePointer(buffer) { outputPointer in
                    libscrypt_scrypt(
                        passwordPointer, password.count,
                        saltPointer, salt.count,
                        parameters.N, parameters.r, parameters.p,
                        outputPointer, parameters.length)
                }
            }
        }
        setSizeTo = status == 0 ? parameters.length : 0
    }

    guard status == 0 else { throw ScryptInternalError() }
    return derived
}
