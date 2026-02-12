#pragma once

#include <vector>
#include <cmath>
#include <iostream>
#include <algorithm>

namespace Monarch {

template<typename T, size_t N>
class VecN {
public:
    // Constructors
    VecN() {
        std::fill(data.begin(), data.end(), T(0));
    }

    explicit VecN(T value) {
        std::fill(data.begin(), data.end(), value);
    }

    VecN(std::initializer_list<T> list) {
        size_t i = 0;
        for (auto val : list) {
            if (i < N) data[i++] = val;
        }
        while (i < N) data[i++] = T(0);
    }

    // Copy constructor
    VecN(const VecN& other) = default;

    // Access operators
    T& operator[](size_t index) { return data[index]; }
    const T& operator[](size_t index) const { return data[index]; }

    // Arithmetic operators
    VecN operator+(const VecN& other) const {
        VecN result;
        for (size_t i = 0; i < N; ++i) {
            result[i] = data[i] + other[i];
        }
        return result;
    }

    VecN operator-(const VecN& other) const {
        VecN result;
        for (size_t i = 0; i < N; ++i) {
            result[i] = data[i] - other[i];
        }
        return result;
    }

    VecN operator*(T scalar) const {
        VecN result;
        for (size_t i = 0; i < N; ++i) {
            result[i] = data[i] * scalar;
        }
        return result;
    }

    VecN operator/(T scalar) const {
        VecN result;
        for (size_t i = 0; i < N; ++i) {
            result[i] = data[i] / scalar;
        }
        return result;
    }

    // Compound assignment operators
    VecN& operator+=(const VecN& other) {
        for (size_t i = 0; i < N; ++i) {
            data[i] += other[i];
        }
        return *this;
    }

    VecN& operator-=(const VecN& other) {
        for (size_t i = 0; i < N; ++i) {
            data[i] -= other[i];
        }
        return *this;
    }

    VecN& operator*=(T scalar) {
        for (size_t i = 0; i < N; ++i) {
            data[i] *= scalar;
        }
        return *this;
    }

    VecN& operator/=(T scalar) {
        for (size_t i = 0; i < N; ++i) {
            data[i] /= scalar;
        }
        return *this;
    }

    // Comparison operators
    bool operator==(const VecN& other) const {
        for (size_t i = 0; i < N; ++i) {
            if (data[i] != other[i]) return false;
        }
        return true;
    }

    bool operator!=(const VecN& other) const {
        return !(*this == other);
    }

    // Vector operations
    T dot(const VecN& other) const {
        T result = T(0);
        for (size_t i = 0; i < N; ++i) {
            result += data[i] * other[i];
        }
        return result;
    }

    T lengthSquared() const {
        return dot(*this);
    }

    T length() const {
        return std::sqrt(lengthSquared());
    }

    VecN normalized() const {
        T len = length();
        if (len > T(0)) {
            return *this / len;
        }
        return VecN(T(0));
    }

    void normalize() {
        *this = normalized();
    }

    // Utility functions
    size_t size() const { return N; }

    T* ptr() { return data.data(); }
    const T* ptr() const { return data.data(); }

    // Static functions
    static VecN zero() { return VecN(T(0)); }
    static VecN one() { return VecN(T(1)); }

private:
    std::array<T, N> data;
};

// Free functions for scalar multiplication (commutative)
template<typename T, size_t N>
VecN<T, N> operator*(T scalar, const VecN<T, N>& vec) {
    return vec * scalar;
}

// Output operator
template<typename T, size_t N>
std::ostream& operator<<(std::ostream& os, const VecN<T, N>& vec) {
    os << "(";
    for (size_t i = 0; i < N; ++i) {
        os << vec[i];
        if (i < N - 1) os << ", ";
    }
    os << ")";
    return os;
}

// Common vector types
using Vec2f = VecN<float, 2>;
using Vec3f = VecN<float, 3>;
using Vec4f = VecN<float, 4>;

using Vec2d = VecN<double, 2>;
using Vec3d = VecN<double, 3>;
using Vec4d = VecN<double, 4>;

using Vec2i = VecN<int, 2>;
using Vec3i = VecN<int, 3>;
using Vec4i = VecN<int, 4>;

} // namespace Monarch
