// Copyright (c) 2017-2023, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote
// developers

#include <sodium/crypto_scalarmult_ed25519.h>

#include "gtest/gtest.h"

// #include "crypto/crypto-ops.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include <sodium.h>

#include <chrono>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "string_tools.h"

using epee::string_tools::hex_to_pod;
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;
using std::chrono::milliseconds;

using namespace rct;

TEST(comparison_mic, scalar_base_mult)
{
    // Perform s*G = P
    rct::key s, P;
    hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", s);
    hex_to_pod("5dec62fb2770a5163db114694c2c9bb73952e5ff41e6f8ff04abe271328d25be", P);
    ASSERT_EQ(P, scalarmultBase(s));
}

TEST(comparison_mic, scalar_mult)
{
    // Perform s*P = K
    rct::key s, P, K, K_test;
    hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", s);
    hex_to_pod("5dec62fb2770a5163db114694c2c9bb73952e5ff41e6f8ff04abe271328d25be", P);
    hex_to_pod("f3c0787cb8eb9ee371d5243cd3cc7b39bbeb1f86f1f1c1f4222918a0686a2f6d", K);

    auto t1 = high_resolution_clock::now();
    // for (int i = 0; i<10; i++)
    scalarmultKey(K_test, P, s);
    auto tt2 = high_resolution_clock::now();

    duration<double, std::milli> ms_double = tt2 - t1;

    std::cout << "Time to execute scalarmult: " << ms_double.count() << "ms\n" << std::endl;

    ASSERT_EQ(K, K_test);
}

TEST(comparison_mic, hash_to_scalar)
{
    key h, s, s_test;
    hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", h);
    hex_to_pod("40ebcf1a61aaaa36218b541b3f509147b0551b15a3a8e0487cabd23ff5c3d80f", s);
    auto t1 = high_resolution_clock::now();
    // for (int i = 0; i<10; i++)
    hash_to_scalar(s_test, h);
    auto tt2 = high_resolution_clock::now();

    duration<double, std::milli> ms_double = tt2 - t1;

    std::cout << "Time to execute hash_to_scalar: " << ms_double.count() << "ms\n" << std::endl;

    ASSERT_EQ(s, s_test);
}

TEST(comparison_mic, hash_to_point)
{
    key h, s, s_test;
    // crypto::ec_point s_test;
    hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", h);
    hex_to_pod("109fa812b31eb2b6bfe21e1eceab7a3072a1d28a0926b05fbd68930f485c2af9", s);

    ge_p3 s_intermediary;
    auto t1 = high_resolution_clock::now();
    hash_to_p3(s_intermediary, h);
    ge_p3_tobytes(s_test.bytes, &s_intermediary);
    auto tt2 = high_resolution_clock::now();

    duration<double, std::milli> ms_double = tt2 - t1;

    std::cout << "Time to execute hash_to_point : " << ms_double.count() << "ms\n" << std::endl;

    ASSERT_EQ(s, s_test);
}

TEST(comparison_mic, bulletproofs_plus)
{
    rct::BulletproofPlus proof = bulletproof_plus_PROVE(crypto::rand<uint64_t>(), rct::skGen());

    hex_to_pod("923427796e77df5b553e23d46a5bd18303bde9cbf3d4276a3455ea0e227e5c97", proof.V[0]);
    // A =
    hex_to_pod("3de5877b144109aafc32686ee90f0162cef3835f25886e234a3bfaf7256c177f", proof.A);
    // A1 =
    hex_to_pod("db27e1e48ab6efb4433c84fc3f7602e093d347fb9be25e94d6a193ab408e50ee", proof.A1);
    // B =
    hex_to_pod("afb8376881c5497afaf125fc98bdc562c6625099d63e1b46de70d7fe5d7a02b6", proof.B);
    // r1 =
    hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", proof.r1);
    // s1 =
    hex_to_pod("3aefdf5d5c959012383ff208742e67b2c41516ba4bc064468cdca5bda4f0240a", proof.s1);
    // d1 =
    hex_to_pod("9351c6530d51b3807cea1cd67b9e7c0f30fd4a6465ed9917effed8673e0f2b09", proof.d1);
    // L = PointVector([])
    hex_to_pod("aeeb3ec51f8a7e4ea09255d928d3c6ab9232d99b3af9e06e9455a61a43ccb5f4", proof.L[0]);
    hex_to_pod("e306c4dcc358b1ced8560e132face7203f362ddd1a8a0c0a86661d36ce7fc136", proof.L[1]);
    hex_to_pod("6c0ceb074889874a9abd22913fe74da05d8782081308bad6a5fdab80dfd88ab6", proof.L[2]);
    hex_to_pod("89fa461e11a2697f7d37b40beb93b4731b15f6cba2e358ae146ff9e6f539c842", proof.L[3]);
    hex_to_pod("3b6df197f741db22676d2d7ba86dda5c958294186468bb9a7473e67f9bf2ab8b", proof.L[4]);
    hex_to_pod("e773322e6bb047291dae4e35c2c517855af121033f3b23fbbff590c7ac4b1693", proof.L[5]);
    // R = PointVector([])
    hex_to_pod("d6efebc0b33845ae143865b6821f8bf715c211f62f3dd976cb346bda729d503d", proof.R[0]);
    hex_to_pod("bac78011b1d8391e1f86d65412e94410c98366525c2b7db3353cf443b43c8bd8", proof.R[1]);
    hex_to_pod("62f8e3bcb0ad17553f19c386f829f5f358a90f5f34ee9217a4086290b544b7e3", proof.R[2]);
    hex_to_pod("5eea37b9f5dfe790c269e9a6bfc813916b35153a69b0a03113a8be7a54ec101b", proof.R[3]);
    hex_to_pod("a9048f32afa538afab193a3eef426528cfbc03344fbfb5c6fcd4ba4c9a9d80b5", proof.R[4]);
    hex_to_pod("3ddd3c95247b4f48f532a788c616c2570ac3cf9ffcd04e5373112c36c27fcacf", proof.R[5]);

    auto t1 = high_resolution_clock::now();
    // for (int i = 0; i<10; i++)
    ASSERT_TRUE(rct::bulletproof_plus_VERIFY(proof));
    auto t2 = high_resolution_clock::now();

    /* Getting number of milliseconds as a double. */
    duration<double, std::milli> ms_double = t2 - t1;

    std::cout << "Time to verify BP+ : " << ms_double.count() << "ms\n" << std::endl;
}

TEST(comparison_mic, clsag)
{
    const size_t N   = 16;
    const size_t idx = 5;
    ctkeyV pubs;
    key p, t, t2, u;
    const key message = identity();
    ctkey backup;
    clsag clsag;

    for (size_t i = 0; i < N; ++i)
    {
        key sk;
        ctkey tmp;

        skpkGen(sk, tmp.dest);
        skpkGen(sk, tmp.mask);

        pubs.push_back(tmp);
    }

    // Set P[idx]
    skpkGen(p, pubs[idx].dest);

    // Set C[idx]
    t = skGen();
    u = skGen();
    addKeys2(pubs[idx].mask, t, u, H);

    // Set commitment offset
    key Cout;
    t2 = skGen();
    addKeys2(Cout, t2, u, H);

    // Prepare generation inputs
    ctkey insk;
    insk.dest = p;
    insk.mask = t;

    clsag = rct::proveRctCLSAGSimple(message, pubs, insk, t2, Cout, idx, hw::get_device("default"));

    auto t1 = high_resolution_clock::now();
    // for (int i = 0; i<10; i++)
    ASSERT_TRUE(rct::verRctCLSAGSimple(message, clsag, pubs, Cout));
    auto tt2 = high_resolution_clock::now();

    /* Getting number of milliseconds as a double. */
    duration<double, std::milli> ms_double = tt2 - t1;

    std::cout << "Time to verify CLSAG: " << ms_double.count() << "ms\n" << std::endl;
}

// TEST(comparison_mic, libsodium)
// {
//     //////////////////////////////////////
//     /// OPERATIONS USING MONERO LIBRARY
//     //////////////////////////////////////

//     rct::key scalar;
//     epee::string_tools::hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", scalar);

//     auto t1_op = high_resolution_clock::now();
//     // for (int i = 0; i< 1000; i++)
//     auto res   = rct::scalarmultKey(rct::G, scalar);
//     auto t2_op = high_resolution_clock::now();

//     /* Getting number of milliseconds as a double. */
//     duration<double, std::milli> ms_double_op = (t2_op - t1_op);

//     auto t1_op_b = high_resolution_clock::now();
//     // for (int i = 0; i< 1000; i++)
//     res          = rct::scalarmultBase(scalar);
//     auto t2_op_b = high_resolution_clock::now();

//     /* Getting number of milliseconds as a double. */
//     duration<double, std::milli> ms_double_op_b = (t2_op_b - t1_op_b);

//     // time to add
//     rct::key result;
//     auto t1_a = high_resolution_clock::now();
//     // for (int i = 0; i< 1000; i++)
//     for (int i = 0; i < 1000; i++) sc_add(result.bytes, scalar.bytes, scalar.bytes);
//     auto t2_a = high_resolution_clock::now();

//     /* Getting number of milliseconds as a double. */
//     duration<double, std::milli> ms_double_a = (t2_a - t1_a) / 1000;

//     std::cout << "Average time of a single point multiplication : " << ms_double_op.count() << "ms\n" << std::endl;
//     std::cout << "Average time of a single base point multiplication : " << ms_double_op_b.count() << "ms\n"
//               << std::endl;
//     std::cout << "Average time of an addition: " << ms_double_a.count() << "ms\n" << std::endl;

//     //////////////////////////////////////
//     // USING SODIUM
//     //////////////////////////////////////

//     rct::key scalar_s;
//     unsigned char r[crypto_core_ed25519_SCALARBYTES];
//     unsigned char gr[crypto_core_ed25519_BYTES];
//     unsigned char a[crypto_core_ed25519_BYTES];
//     epee::string_tools::hex_to_pod("21ab1f46a2c7efd314349640f585c3fd4fbe71d92a8b58aa092d20db72b25c00", r);

//     // crypto_core_ed25519_scalar_random(r);

//     auto t1_ops = high_resolution_clock::now();
//     // for (int i = 0; i< 1000; i++)
//     crypto_scalarmult_ed25519_noclamp(gr, rct::G.bytes, r);
//     auto t2_ops = high_resolution_clock::now();

//     /* Getting number of milliseconds as a double. */
//     duration<double, std::milli> ms_double_ops = (t2_ops - t1_ops);

//     auto t1_op_bs = high_resolution_clock::now();
//     // for (int i = 0; i< 1000; i++)
//     crypto_scalarmult_ed25519_base_noclamp(gr, r);
//     auto t2_op_bs = high_resolution_clock::now();

//     /* Getting number of milliseconds as a double. */
//     duration<double, std::milli> ms_double_op_bs = (t2_op_bs - t1_op_bs);

//     // time to add
//     // rct::key result;
//     // auto t1_a = high_resolution_clock::now();
//     // // for (int i = 0; i< 1000; i++)
//     // for (int i=0;i<1000;i++)
//     //   sc_add(result.bytes, proof.r1.bytes, proof.s1.bytes);
//     // auto t2_a = high_resolution_clock::now();

//     /* Getting number of milliseconds as a double. */
//     // duration<double, std::milli> ms_double_a = (t2_a - t1_a)/1000;

//     std::cout << "Average time of a single point multiplication libsodium: " << ms_double_ops.count() << "ms\n"
//               << std::endl;
//     std::cout << "Average time of a single base point multiplication libsodium: " << ms_double_op_bs.count() << "ms\n"
//               << std::endl;
//     // std::cout << "Average time of an addition: " << ms_double_a.count() <<
//     // "ms\n" << std::endl;
// }

