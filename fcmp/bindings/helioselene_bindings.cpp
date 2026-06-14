#include <openssl/types.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <pybind11/pybind11.h>
#include <stdexcept>
#include <string>
#include <algorithm>

namespace py = pybind11;

// =======================================================
// GLOBAL CONTEXT
// =======================================================
BN_CTX* ctx = BN_CTX_new();

EC_GROUP* selene_group = nullptr;
EC_GROUP* helios_group = nullptr;


// =======================================================
// CURVE INIT
// =======================================================
EC_GROUP* get_selene() {
    if (selene_group) return selene_group;

    BIGNUM *p = BN_new(), *a = nullptr, *b = nullptr;

    BN_hex2bn(&p, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF735481D1969F317F9850B68DF11DF53");

    a = BN_dup(p);
    BN_sub_word(a, 3);

    BN_dec2bn(&b, "25675911719867737339625140396204798989996478324626569376465022644547366285284");

    selene_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);

    BN_free(p); BN_free(a); BN_free(b);
    return selene_group;
}

EC_GROUP* get_helios() {
    if (helios_group) return helios_group;

    BIGNUM *p = BN_new(), *a = nullptr, *b = nullptr;

    BN_one(p);
    BN_lshift(p, p, 255);
    BN_sub_word(p, 19);

    a = BN_dup(p);
    BN_sub_word(a, 3);

    BN_dec2bn(&b, "17523451383230374900436292617863907649717438939964238673872692863501483215968");

    helios_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);

    BN_free(p); BN_free(a); BN_free(b);
    return helios_group;
}


// =======================================================
// SHARED HELPERS
// =======================================================

void set_xy(EC_GROUP* group, EC_POINT* P,
            const std::string& x_hex, const std::string& y_hex) {

    BIGNUM *x = nullptr, *y = nullptr;
    BN_hex2bn(&x, x_hex.c_str());
    BN_hex2bn(&y, y_hex.c_str());

    EC_POINT_set_affine_coordinates(group, P, x, y, ctx);

    BN_free(x); BN_free(y);
}

std::string normalize_hex(const std::string& input) {
    std::string hex = input;

    // 1. convert to lowercase
    std::transform(hex.begin(), hex.end(), hex.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // 2. pad with leading zeros to 64 characters
    if (hex.size() > 64) {
        throw std::runtime_error("Hex string longer than 64 characters");
    }

    return std::string(64 - hex.size(), '0') + hex;
}

std::string point_repr(EC_GROUP* group, EC_POINT* P, const std::string& name) {
    BIGNUM *x = BN_new(), *y = BN_new();

    if (!EC_POINT_get_affine_coordinates(group, P, x, y, ctx)) {
        BN_free(x); BN_free(y);
        return "<" + name + " INF>";
    }

    char* xs = BN_bn2hex(x);
    char* ys = BN_bn2hex(y);

    std::string out = name + "(x=" + normalize_hex(xs) + ", y=" + normalize_hex(ys) + ")";

    OPENSSL_free(xs);
    OPENSSL_free(ys);
    BN_free(x); BN_free(y);

    return out;
}


std::string coordinate_repr(EC_GROUP* group, EC_POINT* P, const std::string& name) {
    BIGNUM *x = BN_new(), *y = BN_new();

    if (!EC_POINT_get_affine_coordinates(group, P, x, y, ctx)) {
        BN_free(x); BN_free(y);
        return "<" + name + " INF>";
    }

    char* xs = BN_bn2hex(x);
    char* ys = BN_bn2hex(y);

    std::string out;
    if (name == "x") {
        out = normalize_hex(xs);
    }
    else if (name == "y") {
        out = normalize_hex(ys);
    }
    else {
        out = "Not defined";
    }

    OPENSSL_free(xs);
    OPENSSL_free(ys);
    BN_free(x); BN_free(y);

    return out;
}

std::string scalar_repr(BIGNUM* k) {
    char* ks = BN_bn2hex(k);
    std::string out = normalize_hex(ks);
    OPENSSL_free(ks);
    return out;
}

// =======================================================
// SCALAR
// =======================================================
class Scalar {
public:
    BIGNUM* k;

    Scalar() {
        k = BN_new();
    }

    Scalar(const std::string& hex) {
        k = BN_new();
        BN_hex2bn(&k, hex.c_str());
    }

    void set_scalar(const std::string& hex_str) {
        k = BN_new();
        BN_hex2bn(&k, hex_str.c_str());
    }

    ~Scalar() {
        BN_free(k);
    }

    std::string repr() const {
        return scalar_repr(k);
    }

};

// =======================================================
// SELENE POINT
// =======================================================
class SelenePoint {
public:
    EC_POINT* P;

    SelenePoint() {
        P = EC_POINT_new(get_selene());
    }

    SelenePoint(const SelenePoint& other) {
        P = EC_POINT_dup(other.P, get_selene());
    }

    ~SelenePoint() {
        EC_POINT_free(P);
    }

    void set_xy(const std::string& x, const std::string& y) {
        ::set_xy(get_selene(), P, x, y);
    }

    SelenePoint operator+(const SelenePoint& other) const {
        SelenePoint R;
        EC_POINT_add(get_selene(), R.P, this->P, other.P, ctx);
        return R;
    }

    std::string repr() const {
        return point_repr(get_selene(), P, "SelenePoint");
    }

    std::string x() const {
        return coordinate_repr(get_selene(), P, "x");
    }

    std::string y() const {
        return coordinate_repr(get_selene(), P, "y");
    }
};


// =======================================================
// HELIOS POINT
// =======================================================
class HeliosPoint {
public:
    EC_POINT* P;

    HeliosPoint() {
        P = EC_POINT_new(get_helios());
    }

    HeliosPoint(const HeliosPoint& other) {
        P = EC_POINT_dup(other.P, get_helios());
    }

    ~HeliosPoint() {
        EC_POINT_free(P);
    }

    void set_xy(const std::string& x, const std::string& y) {
        ::set_xy(get_helios(), P, x, y);
    }

    HeliosPoint operator+(const HeliosPoint& other) const {
        HeliosPoint R;
        EC_POINT_add(get_helios(), R.P, this->P, other.P, ctx);
        return R;
    }

    std::string repr() const {
        return point_repr(get_helios(), P, "HeliosPoint");
    }

    std::string x() const {
        return coordinate_repr(get_helios(), P, "x");
    }

    std::string y() const {
        return coordinate_repr(get_helios(), P, "y");
    }
};


// =======================================================
// SCALAR MULTIPLICATION
// =======================================================
SelenePoint selene_mul(const Scalar& k, const SelenePoint& P) {
    SelenePoint R;
    EC_POINT_mul(get_selene(), R.P, NULL, P.P, k.k, ctx);
    return R;
}

HeliosPoint helios_mul(const Scalar& k, const HeliosPoint& P) {
    HeliosPoint R;
    EC_POINT_mul(get_helios(), R.P, NULL, P.P, k.k, ctx);
    return R;
}


// =======================================================
// PYBIND11
// =======================================================
PYBIND11_MODULE(helioselene_bindings, m) {

    py::class_<Scalar>(m, "Scalar")
        .def(py::init<>())
        .def(py::init<std::string>())
        .def("__repr__", &Scalar::repr)
        .def("set_scalar", &Scalar::set_scalar)
        .def("k", &Scalar::repr);

    py::class_<SelenePoint>(m, "SelenePoint")
        .def(py::init<>())
        .def("set_xy", &SelenePoint::set_xy)
        .def("__add__", [](const SelenePoint& a, const SelenePoint& b) {
            return a + b;
        })
        .def("__rmul__", [](const SelenePoint& P, const Scalar& k) {
            return selene_mul(k, P);
        })
        .def("__repr__", &SelenePoint::repr)
        .def("x", &SelenePoint::x)
        .def("y", &SelenePoint::y);

    py::class_<HeliosPoint>(m, "HeliosPoint")
        .def(py::init<>())
        .def("set_xy", &HeliosPoint::set_xy)
        .def("__add__", [](const HeliosPoint& a, const HeliosPoint& b) {
            return a + b;
        })
        .def("__rmul__", [](const HeliosPoint& P, const Scalar& k) {
            return helios_mul(k, P);
        })
        .def("__repr__", &HeliosPoint::repr)
        .def("x", &HeliosPoint::x)
        .def("y", &HeliosPoint::y);
}