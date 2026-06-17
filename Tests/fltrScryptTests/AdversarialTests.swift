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
// Adversarial / hostile-input regression tests. Several cases here pin down a
// robustness hazard: the old wrapper force-unwrapped the base address of the
// password, salt and output buffers. `Array`'s base address is documented to be
// `nil` for an empty array (and is on some platforms, e.g. Linux), so an empty
// password, empty salt or zero-length output relied on unspecified, platform-
// dependent behaviour that could trap or trigger `memcpy(NULL, …, 0)` UB.
// "Returns the right, well-defined bytes on every platform" IS the assertion.
// The remaining cases drive every branch of libscrypt's parameter validation so
// an invalid request throws rather than allocating gigabytes, over-reading, or
// trapping.
import Testing

@testable import fltrScrypt

@Suite("Adversarial inputs")
struct AdversarialTests {
    // MARK: Empty / zero-length buffers (the force-unwrap hardening)

    /// RFC 7914 §12 vector #1. The old `password.baseAddress!` / `salt.baseAddress!`
    /// depended on an empty `Array` yielding a non-`nil` base address — unspecified
    /// behaviour. This pins the published answer for the empty-password, empty-salt
    /// case so the well-defined result is guaranteed on every platform.
    @Test func emptyPasswordAndSaltMatchesRFCVector() throws {
        let result = try scrypt(password: [], salt: [], parameters: .N(16, r: 1, p: 1, length: 64))
        #expect(
            result.hex == "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                + "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
    }

    @Test func emptyPasswordWithSaltSurvives() throws {
        let withEmpty = try scrypt(
            password: [], salt: "salt".ascii, parameters: .N(16, r: 1, p: 1, length: 32))
        #expect(withEmpty.count == 32)
        // Deterministic: an empty password is a stable, distinct input.
        let again = try scrypt(
            password: [], salt: "salt".ascii, parameters: .N(16, r: 1, p: 1, length: 32))
        #expect(withEmpty == again)
    }

    @Test func emptySaltWithPasswordSurvives() throws {
        let result = try scrypt(
            password: "pw".ascii, salt: [], parameters: .N(16, r: 1, p: 1, length: 32))
        #expect(result.count == 32)
    }

    /// Zero output length exercised `buffer.baseAddress!` on a zero-capacity
    /// buffer; it must return an empty array while still validating the cost
    /// parameters.
    @Test func zeroLengthOutputReturnsEmpty() throws {
        let result = try scrypt(
            password: "pw".ascii, salt: "salt".ascii, parameters: .N(16, r: 1, p: 1, length: 0))
        #expect(result.isEmpty)
    }

    // MARK: Invalid cost parameters must throw, never trap or over-allocate

    /// `N` must be a power of two; libscrypt returns `EINVAL` otherwise.
    @Test(arguments: [UInt64](arrayLiteral: 0, 1, 3, 47, 100, 1000, 65_535))
    func nonPowerOfTwoNThrows(_ n: UInt64) {
        #expect(throws: ScryptInternalError.self) {
            try scrypt(
                password: "pw".ascii, salt: "salt".ascii, parameters: .N(n, r: 1, p: 1, length: 64))
        }
    }

    @Test func zeroRThrows() {
        #expect(throws: ScryptInternalError.self) {
            try scrypt(
                password: "pw".ascii, salt: "salt".ascii,
                parameters: .N(1024, r: 0, p: 1, length: 64))
        }
    }

    @Test func zeroPThrows() {
        #expect(throws: ScryptInternalError.self) {
            try scrypt(
                password: "pw".ascii, salt: "salt".ascii,
                parameters: .N(1024, r: 8, p: 0, length: 64))
        }
    }

    /// `r * p` must stay below 2³⁰. The product 2³⁰ is rejected before any
    /// allocation, so this is cheap despite the enormous nominal factors.
    @Test func rTimesPOverflowThrows() {
        #expect(throws: ScryptInternalError.self) {
            try scrypt(
                password: "pw".ascii, salt: "salt".ascii,
                parameters: .N(2, r: 32_768, p: 32_768, length: 64))
        }
    }

    /// A power-of-two `N` so large the V array (128·r·N bytes) cannot be sized is
    /// rejected by libscrypt's `ENOMEM` guard — *before* it tries to allocate.
    @Test func giganticNThrowsWithoutAllocating() {
        #expect(throws: ScryptInternalError.self) {
            try scrypt(
                password: "pw".ascii, salt: "salt".ascii,
                parameters: .N(UInt64(1) << 60, r: 1, p: 1, length: 64))
        }
    }

    /// A negative output length is outside scrypt's domain. It must throw a clean
    /// `ScryptInternalError` rather than trap inside `Array(unsafeUninitializedCapacity:)`
    /// — otherwise it would crash `try?` callers and break in release builds where a
    /// `precondition` could be elided.
    @Test(arguments: [-1, -64, Int.min])
    func negativeLengthThrows(_ length: Int) {
        #expect(throws: ScryptInternalError.self) {
            try scrypt(
                password: "pw".ascii, salt: "salt".ascii,
                parameters: .N(2, r: 1, p: 1, length: length))
        }
    }

    /// Mirrors how `fltrBIP38` calls the API with `try?`: a rejected parameter set
    /// surfaces as `nil`, not a crash — for both a libscrypt-rejected `N` and the
    /// Swift-side negative-length guard.
    @Test func invalidParametersSurfaceAsNilUnderTryOptional() {
        #expect(
            (try? scrypt(
                password: "pw".ascii, salt: "salt".ascii, parameters: .N(47, r: 1, p: 1, length: 64)
            ))
                == nil)
        #expect(
            (try? scrypt(
                password: "pw".ascii, salt: "salt".ascii, parameters: .N(2, r: 1, p: 1, length: -1)
            ))
                == nil)
    }

    // MARK: Hostile-but-valid payloads

    /// Binary keys covering every byte value, both longer than the 64-byte HMAC
    /// block (so the password takes the "key is SHA-256(key)" path) — must derive
    /// stable output without choking on NUL or high bytes.
    @Test func fullByteRangeBinaryInputRoundTrips() throws {
        let allBytes = (0...255).map { UInt8($0) }
        let first = try scrypt(
            password: allBytes, salt: allBytes, parameters: .N(64, r: 4, p: 2, length: 64))
        #expect(first.count == 64)
        let second = try scrypt(
            password: allBytes, salt: allBytes, parameters: .N(64, r: 4, p: 2, length: 64))
        #expect(first == second)
    }

    /// The minimum legal cost (`N == 2`) must succeed.
    @Test func minimumNSucceeds() throws {
        let result = try scrypt(
            password: "pw".ascii, salt: "salt".ascii, parameters: .N(2, r: 1, p: 1, length: 64))
        #expect(result.count == 64)
    }

    /// Output length is honoured exactly across PBKDF2 block boundaries (32 bytes),
    /// including the partial-final-block and zero cases.
    @Test(arguments: [0, 1, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 256])
    func outputLengthIsHonoured(_ length: Int) throws {
        let result = try scrypt(
            password: "pw".ascii, salt: "salt".ascii, parameters: .N(2, r: 1, p: 1, length: length))
        #expect(result.count == length)
    }

    /// Distinct salts with an otherwise identical request yield distinct keys.
    @Test func saltSeparationChangesOutput() throws {
        let a = try scrypt(
            password: "pw".ascii, salt: "salt-a".ascii, parameters: .N(16, r: 1, p: 1, length: 32))
        let b = try scrypt(
            password: "pw".ascii, salt: "salt-b".ascii, parameters: .N(16, r: 1, p: 1, length: 32))
        #expect(a != b)
    }
}
