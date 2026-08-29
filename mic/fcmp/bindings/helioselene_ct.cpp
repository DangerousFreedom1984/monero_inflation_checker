// Constant-time Selene/Helios EC bindings
//

// `ct_mul` is the constant-time Montgomery ladder, for secret
// scalars. 
// 
// `straus` and `msm`, both compute sum(k_i * P_i) for public
// scalars 
//
// ---- Why two multiexps -----------------------------------------------------
//
// Because we can overcome their limitations if we combine them.
//
// `msm` is Pippenger's bucket method. It sorts terms into buckets by scalar digit
// and aggregates once per window, so its cost per term falls as terms are added.
// But it also has a floor: the bucket array is walked once per window no
// matter how few terms there are. 
//
// `straus` is interleaved wNAF (windowed Non-Adjacent Form) over a single 
// shared doubling chain. It has almost no fixed cost, so it starts far ahead,
// but nothing is shared between terms beyond the doubling chain, 
// so its cost per term never improves.
//
// For example, a measurement on Selene:
//
//        terms      straus        msm    winner
//            2       345 us     604 us    straus 1.75x
//            8       690 us    1057 us    straus 1.53x
//           32      2194 us    2413 us    straus 1.10x
//           48      3396 us    3232 us    msm    1.05x
//          256     16856 us   11606 us    msm    1.45x
//         2048    152293 us   69400 us    msm    2.19x
//
// So multiexp.py keeps both and switches at the crossover
// STRAUS_MAX_TERMS = 48 
//

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace py = pybind11;

static BN_CTX* ctx = BN_CTX_new();
static EC_GROUP* selene_group = nullptr;
static EC_GROUP* helios_group = nullptr;

static const char* SELENE_P  = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF735481D1969F317F9850B68DF11DF53";
static const char* SELENE_B  = "25675911719867737339625140396204798989996478324626569376465022644547366285284";
static const char* SELENE_GY = "39098C0A54BD9D2781C7D734720D5CA639EE79DEEEFCD74517FCED93AD6635C0";
static const char* HELIOS_B  = "17523451383230374900436292617863907649717438939964238673872692863501483215968";
static const char* HELIOS_GY = "611DFFC62FE02C759E5AC10F40E009B8E3B147387068AAF810DBDF2D817C67BA";

// Register generator (1, gy) with `order`, cofactor 1 -> enables the CT ladder.
static void set_ct_generator(EC_GROUP* g, const char* gy_hex, BIGNUM* order) {
    BIGNUM *gx = nullptr, *gy = nullptr, *cof = BN_new();
    BN_hex2bn(&gx, "1");
    BN_hex2bn(&gy, gy_hex);
    BN_one(cof);
    EC_POINT* G = EC_POINT_new(g);
    if (!EC_POINT_set_affine_coordinates(g, G, gx, gy, ctx))
        throw std::runtime_error("generator not on curve");
    if (!EC_GROUP_set_generator(g, G, order, cof))
        throw std::runtime_error("EC_GROUP_set_generator failed");
    EC_POINT_free(G); BN_free(gx); BN_free(gy); BN_free(cof);
}

static EC_GROUP* get_selene() {
    if (selene_group) return selene_group;
    BIGNUM *p = BN_new(), *a = nullptr, *b = nullptr, *order = BN_new();
    BN_hex2bn(&p, SELENE_P);
    a = BN_dup(p); BN_sub_word(a, 3);
    BN_dec2bn(&b, SELENE_B);
    selene_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    BN_one(order); BN_lshift(order, order, 255); BN_sub_word(order, 19);  // 2^255-19
    set_ct_generator(selene_group, SELENE_GY, order);
    BN_free(p); BN_free(a); BN_free(b); BN_free(order);
    return selene_group;
}

static EC_GROUP* get_helios() {
    if (helios_group) return helios_group;
    BIGNUM *p = BN_new(), *a = nullptr, *b = nullptr, *order = nullptr;
    BN_one(p); BN_lshift(p, p, 255); BN_sub_word(p, 19);  // 2^255-19
    a = BN_dup(p); BN_sub_word(a, 3);
    BN_dec2bn(&b, HELIOS_B);
    helios_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    BN_hex2bn(&order, SELENE_P);  // Helios order = Selene base prime
    set_ct_generator(helios_group, HELIOS_GY, order);
    BN_free(p); BN_free(a); BN_free(b); BN_free(order);
    return helios_group;
}

static std::string norm_hex(const std::string& in) {
    std::string h = in;
    std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c){ return std::tolower(c); });
    if (h.size() > 64) throw std::runtime_error("hex too long");
    return std::string(64 - h.size(), '0') + h;
}

class Scalar {
public:
    BIGNUM* k;
    Scalar() { k = BN_new(); }
    Scalar(const std::string& hex) { k = BN_new(); BN_hex2bn(&k, hex.c_str()); }
    ~Scalar() { BN_free(k); }
    std::string repr() const { char* s = BN_bn2hex(k); std::string o = norm_hex(s); OPENSSL_free(s); return o; }
};

template <EC_GROUP* (*G)()>
class Pt {
public:
    EC_POINT* P;
    Pt() { P = EC_POINT_new(G()); }
    Pt(const Pt& o) { P = EC_POINT_dup(o.P, G()); }
    ~Pt() { EC_POINT_free(P); }
    void set_xy(const std::string& x, const std::string& y) {
        BIGNUM *bx = nullptr, *by = nullptr;
        BN_hex2bn(&bx, x.c_str()); BN_hex2bn(&by, y.c_str());
        EC_POINT_set_affine_coordinates(G(), P, bx, by, ctx);
        BN_free(bx); BN_free(by);
    }
    Pt operator+(const Pt& o) const { Pt R; EC_POINT_add(G(), R.P, P, o.P, ctx); return R; }
    std::string coord(bool wantx) const {
        BIGNUM *x = BN_new(), *y = BN_new();
        if (!EC_POINT_get_affine_coordinates(G(), P, x, y, ctx)) { BN_free(x); BN_free(y); return "<INF>"; }
        char* s = BN_bn2hex(wantx ? x : y); std::string o = norm_hex(s);
        OPENSSL_free(s); BN_free(x); BN_free(y); return o;
    }
    std::string x() const { return coord(true); }
    std::string y() const { return coord(false); }
};

using SelenePoint = Pt<get_selene>;
using HeliosPoint = Pt<get_helios>;

// ---- constant-time scalar multiplication: k*P via the Montgomery ladder ----
template <EC_GROUP* (*G)()>
static Pt<G> ct_mul(const Scalar& k, const Pt<G>& P) {
    Pt<G> R;
    BN_set_flags(k.k, BN_FLG_CONSTTIME);  // treat the scalar as secret
    if (!EC_POINT_mul(G(), R.P, nullptr, P.P, k.k, ctx))
        throw std::runtime_error("EC_POINT_mul failed");
    return R;
}

// ---- Straus (interleaved wNAF) for fast PUBLIC multiexps with FEW terms ----
//
// The bucket MSM below pays for its buckets once per window whatever the term
// count, which at 2 terms is thousands of point operations to add two points. It
// measured slower there than one scalar multiplication per term. Straus shares a
// single doubling chain across all terms instead, so it wins until there are
// enough terms to amortize those buckets. multiexp.py holds the crossover in
// STRAUS_MAX_TERMS 
//
// Variable-time by construction: the digits steer the additions. PUBLIC scalars
// only, same contract as msm().

static const int STRAUS_W = 5;  // window width. Table is 2^(w-2) odd multiples

// width-w NAF. Digits are 0 or odd with |d| < 2^(w-1). Consumes a copy of k.
static std::vector<int> wnaf(const BIGNUM* k, int w) {
    std::vector<int> naf;
    BIGNUM* t = BN_dup(k);
    const int half = 1 << (w - 1), full = 1 << w;
    while (!BN_is_zero(t)) {
        int d = 0;
        if (BN_is_odd(t)) {
            int m = 0;
            for (int b = 0; b < w; b++)
                if (BN_is_bit_set(t, b)) m |= (1 << b);
            d = (m >= half) ? m - full : m;
            if (d > 0) BN_sub_word(t, (BN_ULONG)d);
            else        BN_add_word(t, (BN_ULONG)(-d));
        }
        naf.push_back(d);
        BN_rshift1(t, t);
    }
    BN_free(t);
    return naf;
}

// Odd multiples 1P, 3P, ..., (2^(w-1)-1)P. Caller frees.
template <EC_GROUP* (*G)()>
static void odd_table(const EC_POINT* P, int w, std::vector<EC_POINT*>& tab) {
    EC_GROUP* g = G();
    const int n = 1 << (w - 2);
    tab.resize(n);
    tab[0] = EC_POINT_dup(P, g);
    EC_POINT* two = EC_POINT_new(g);
    EC_POINT_dbl(g, two, P, ctx);
    for (int i = 1; i < n; i++) {
        tab[i] = EC_POINT_new(g);
        EC_POINT_add(g, tab[i], tab[i - 1], two, ctx);
    }
    EC_POINT_free(two);
}

template <EC_GROUP* (*G)()>
static Pt<G> straus(const std::vector<std::string>& ks,
                    const std::vector<std::string>& xs,
                    const std::vector<std::string>& ys) {
    EC_GROUP* g = G();
    size_t n = ks.size();
    Pt<G> RES;  // starts at infinity
    if (n == 0) return RES;

    std::vector<std::vector<int>> nafs(n);
    std::vector<std::vector<EC_POINT*>> tabs(n);
    size_t maxlen = 0;
    for (size_t i = 0; i < n; i++) {
        BIGNUM* k = nullptr;
        BN_hex2bn(&k, ks[i].c_str());
        nafs[i] = wnaf(k, STRAUS_W);
        BN_free(k);
        maxlen = std::max(maxlen, nafs[i].size());

        EC_POINT* P = EC_POINT_new(g);
        BIGNUM *bx = nullptr, *by = nullptr;
        BN_hex2bn(&bx, xs[i].c_str()); BN_hex2bn(&by, ys[i].c_str());
        EC_POINT_set_affine_coordinates(g, P, bx, by, ctx);
        BN_free(bx); BN_free(by);
        odd_table<G>(P, STRAUS_W, tabs[i]);
        EC_POINT_free(P);
    }

    // One doubling chain, every term's digit added at each step.
    EC_POINT* scratch = EC_POINT_new(g);
    for (int j = (int)maxlen - 1; j >= 0; j--) {
        EC_POINT_dbl(g, RES.P, RES.P, ctx);
        for (size_t i = 0; i < n; i++) {
            if (j >= (int)nafs[i].size()) continue;
            int d = nafs[i][j];
            if (d == 0) continue;
            const EC_POINT* T = tabs[i][(std::abs(d) - 1) / 2];
            if (d > 0) {
                EC_POINT_add(g, RES.P, RES.P, T, ctx);
            } else {
                EC_POINT_copy(scratch, T);
                EC_POINT_invert(g, scratch, ctx);
                EC_POINT_add(g, RES.P, RES.P, scratch, ctx);
            }
        }
    }
    EC_POINT_free(scratch);

    for (auto& tab : tabs)
        for (EC_POINT* p : tab) EC_POINT_free(p);
    return RES;
}

// ---- native Pippenger MSM (bucket method) for fast PUBLIC multiexps ----
//
// Two things that it does:
//
//   signed digits    each c-bit digit is folded into (-2^(c-1), 2^(c-1)] with a
//                    carry, so only half as many buckets are needed. Negating a
//                    point is free here, so the sign costs nothing.
//   no clearing      buckets carry a generation stamp instead of being reset
//                    every window. Untouched buckets are skipped rather than
//                    zeroed, which used to dominate at low term counts.
//
// Still variable-time in the scalars: which bucket a term lands in is its digit.
// PUBLIC scalars only.

template <EC_GROUP* (*G)()>
static Pt<G> msm(const std::vector<std::string>& ks,
                 const std::vector<std::string>& xs,
                 const std::vector<std::string>& ys) {
    EC_GROUP* g = G();
    size_t n = ks.size();
    Pt<G> RES;  // starts at infinity
    if (n == 0) return RES;

    std::vector<BIGNUM*> sc(n);
    std::vector<EC_POINT*> pt(n);
    int maxbits = 1;
    for (size_t i = 0; i < n; i++) {
        sc[i] = BN_new();
        BN_hex2bn(&sc[i], ks[i].c_str());
        maxbits = std::max(maxbits, BN_num_bits(sc[i]));

        pt[i] = EC_POINT_new(g);
        BIGNUM *bx = nullptr, *by = nullptr;
        BN_hex2bn(&bx, xs[i].c_str()); BN_hex2bn(&by, ys[i].c_str());
        EC_POINT_set_affine_coordinates(g, pt[i], bx, by, ctx);
        BN_free(bx); BN_free(by);
    }

    int c = 4; while ((1 << (c + 1)) < (int)n && c < 12) c++;  // window ~ log2(n)
    const int half = 1 << (c - 1);          // signed digits live in [1, half]
    const int nb = half + 1;                // index 0 unused, keeps arithmetic plain
    // One extra window absorbs a carry out of the top digit.
    const int nwin = (maxbits + c - 1) / c + 1;

    // Signed digits, all windows, all terms. digits[i*nwin + w].
    std::vector<int> digits((size_t)n * nwin, 0);
    for (size_t i = 0; i < n; i++) {
        int carry = 0;
        for (int w = 0; w < nwin; w++) {
            int d = 0;
            for (int b = 0; b < c; b++)
                if (BN_is_bit_set(sc[i], w * c + b)) d |= (1 << b);
            d += carry;
            if (d > half) { d -= (1 << c); carry = 1; } else { carry = 0; }
            digits[(size_t)i * nwin + w] = d;
        }
    }

    std::vector<EC_POINT*> buckets(nb, nullptr);
    std::vector<int> stamp(nb, -1);         // window this bucket was last written in
    for (int j = 1; j < nb; j++) buckets[j] = EC_POINT_new(g);
    EC_POINT* running = EC_POINT_new(g);
    EC_POINT* acc = EC_POINT_new(g);
    EC_POINT* neg = EC_POINT_new(g);

    for (int w = nwin - 1; w >= 0; w--) {
        for (int d = 0; d < c; d++) EC_POINT_dbl(g, RES.P, RES.P, ctx);

        for (size_t i = 0; i < n; i++) {
            int d = digits[(size_t)i * nwin + w];
            if (d == 0) continue;
            int j = d > 0 ? d : -d;
            const EC_POINT* addend = pt[i];
            if (d < 0) { EC_POINT_copy(neg, pt[i]); EC_POINT_invert(g, neg, ctx); addend = neg; }
            if (stamp[j] != w) {            // first touch this window: assign, do not add
                EC_POINT_copy(buckets[j], addend);
                stamp[j] = w;
            } else {
                EC_POINT_add(g, buckets[j], buckets[j], addend, ctx);
            }
        }

        EC_POINT_set_to_infinity(g, running);
        EC_POINT_set_to_infinity(g, acc);
        bool running_live = false;
        for (int j = nb - 1; j >= 1; j--) {
            if (stamp[j] == w) {
                EC_POINT_add(g, running, running, buckets[j], ctx);
                running_live = true;
            }
            if (running_live) EC_POINT_add(g, acc, acc, running, ctx);
        }
        EC_POINT_add(g, RES.P, RES.P, acc, ctx);
    }

    for (int j = 1; j < nb; j++) EC_POINT_free(buckets[j]);
    EC_POINT_free(running); EC_POINT_free(acc); EC_POINT_free(neg);
    for (size_t i = 0; i < n; i++) { BN_free(sc[i]); EC_POINT_free(pt[i]); }
    return RES;
}

PYBIND11_MODULE(helioselene_ct, m) {
    py::class_<Scalar>(m, "Scalar", py::module_local())
        .def(py::init<>())
        .def(py::init<std::string>())
        .def("__repr__", &Scalar::repr)
        .def("k", &Scalar::repr);

    py::class_<SelenePoint>(m, "SelenePoint", py::module_local())
        .def(py::init<>())
        .def("set_xy", &SelenePoint::set_xy)
        .def("__add__", [](const SelenePoint& a, const SelenePoint& b) { return a + b; })
        .def("__rmul__", [](const SelenePoint& P, const Scalar& k) { return ct_mul<get_selene>(k, P); })
        .def("x", &SelenePoint::x)
        .def("y", &SelenePoint::y);

    py::class_<HeliosPoint>(m, "HeliosPoint", py::module_local())
        .def(py::init<>())
        .def("set_xy", &HeliosPoint::set_xy)
        .def("__add__", [](const HeliosPoint& a, const HeliosPoint& b) { return a + b; })
        .def("__rmul__", [](const HeliosPoint& P, const Scalar& k) { return ct_mul<get_helios>(k, P); })
        .def("x", &HeliosPoint::x)
        .def("y", &HeliosPoint::y);

    m.def("selene_msm", &msm<get_selene>, "native Pippenger MSM over Selene (public)");
    m.def("helios_msm", &msm<get_helios>, "native Pippenger MSM over Helios (public)");

    m.def("selene_straus", &straus<get_selene>, "interleaved-wNAF multiexp, few terms (public)");
    m.def("helios_straus", &straus<get_helios>, "interleaved-wNAF multiexp, few terms (public)");
}
