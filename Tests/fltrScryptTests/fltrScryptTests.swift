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
import Testing

@testable import fltrScrypt

// MARK: - Known-answer vectors

/// A published scrypt known-answer vector.
private struct KnownAnswer: Sendable, CustomTestStringConvertible {
    let password: String
    let salt: String
    let parameters: ScryptParameters
    /// The expected derived key, lowercase hex.
    let expected: String

    var testDescription: String {
        let p = "N=\(parameters.N) r=\(parameters.r) p=\(parameters.p) len=\(parameters.length)"
        return "scrypt(P=\"\(password)\", S=\"\(salt)\", \(p))"
    }
}

/// The fast RFC 7914 §12 vectors (the three that run in well under a second).
private let rfc7914Vectors: [KnownAnswer] = [
    // scrypt (P="", S="", N=16, r=1, p=1, dkLen=64) — exercises the empty
    // password *and* empty salt path the old wrapper handled only via
    // unspecified `Array.baseAddress` behaviour.
    KnownAnswer(
        password: "",
        salt: "",
        parameters: .N(16, r: 1, p: 1, length: 64),
        expected: "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            + "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    ),
    // scrypt (P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64)
    KnownAnswer(
        password: "password",
        salt: "NaCl",
        parameters: .N(1024, r: 8, p: 16, length: 64),
        expected: "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
            + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
    ),
    // scrypt (P="pleaseletmein", S="SodiumChloride", N=16384, r=8, p=1, dkLen=64)
    KnownAnswer(
        password: "pleaseletmein",
        salt: "SodiumChloride",
        parameters: .N(16384, r: 8, p: 1, length: 64),
        expected: "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
            + "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    ),
]

@Suite("scrypt RFC 7914 known answers")
struct KnownAnswerTests {
    @Test("Derived key matches the published vector", arguments: rfc7914Vectors)
    private func matchesPublishedVector(_ vector: KnownAnswer) throws {
        let result = try scrypt(
            password: vector.password.ascii,
            salt: vector.salt.ascii,
            parameters: vector.parameters
        )
        #expect(result.count == vector.parameters.length)
        #expect(result.hex == vector.expected)
    }

    /// The fourth RFC 7914 vector uses N = 2²⁰, allocating ~1 GiB for the V array
    /// and taking a few seconds. Kept separate so the fast suite stays instant.
    @Test("Large-N RFC 7914 vector (N = 1048576, ~1 GiB)", .timeLimit(.minutes(2)))
    private func largeNVector() throws {
        let result = try scrypt(
            password: "pleaseletmein".ascii,
            salt: "SodiumChloride".ascii,
            parameters: .N(1_048_576, r: 8, p: 1, length: 64)
        )
        #expect(
            result.hex == "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa47"
                + "8e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"
        )
    }
}

// MARK: - Public-API contract

@Suite("Public API contract")
struct ContractTests {
    /// `fltrBIP38` derives keys with these three presets; the exact cost/length
    /// values are part of the published contract and must not drift.
    @Test func bip38PresetsHaveExpectedParameters() {
        #expect(ScryptParameters.bip38nonmul == .N(16384, r: 8, p: 8, length: 64))
        #expect(ScryptParameters.bip38intermediate == .N(16384, r: 8, p: 8, length: 32))
        #expect(ScryptParameters.bip38mul == .N(1024, r: 1, p: 1, length: 64))
    }

    @Test func bip38PresetsProduceCorrectlySizedOutput() throws {
        #expect(
            try scrypt(password: "pw".ascii, salt: "salt".ascii, parameters: .bip38nonmul).count
                == 64)
        #expect(
            try scrypt(password: "pw".ascii, salt: "salt".ascii, parameters: .bip38intermediate)
                .count
                == 32)
        #expect(
            try scrypt(password: "pw".ascii, salt: "salt".ascii, parameters: .bip38mul).count == 64)
    }

    /// The factory and the synthesized value semantics agree.
    @Test func parametersAreValueEquatable() {
        let a: ScryptParameters = .N(1024, r: 8, p: 1, length: 32)
        let b: ScryptParameters = .N(1024, r: 8, p: 1, length: 32)
        let c: ScryptParameters = .N(1024, r: 8, p: 1, length: 64)
        #expect(a == b)
        #expect(a != c)
        #expect(Set([a, b, c]).count == 2)
        #expect(a.N == 1024 && a.r == 8 && a.p == 1 && a.length == 32)
    }

    /// Scrypt is a pure function: identical inputs yield identical output.
    @Test func derivationIsDeterministic() throws {
        let first = try scrypt(
            password: "deterministic".ascii,
            salt: "salt".ascii,
            parameters: .N(256, r: 4, p: 2, length: 48))
        let second = try scrypt(
            password: "deterministic".ascii,
            salt: "salt".ascii,
            parameters: .N(256, r: 4, p: 2, length: 48))
        #expect(first == second)
    }
}
