//
// Created by george on 11/11/2017.
//

#include "SerializeObjects.h"

void ExportN(stringstream &out, const ZZ &val) {
    uint32_t nBytes = NumBytes(val);
    out.write((char *) &nBytes, sizeof(uint32_t));

    bool neg = (val < 0);
    out.write((char *) &neg, sizeof(bool));

    unsigned char data[nBytes];
    BytesFromZZ(data, val, nBytes);
    out.write((char *) data, nBytes);
}

void ImportN(ifstream &in, ZZ &val) {
    uint32_t nBytes;
    in.read((char *) &nBytes, sizeof(uint32_t));

    bool neg;
    in.read((char *) &neg, sizeof(bool));

    unsigned char data[nBytes];
    in.read((char *) data, nBytes);
    ZZFromBytes(val, data, nBytes);

    if (neg) val *= -1;
}

void ExportN(stringstream &out, const ZZX &poly) {
    int32_t degree = deg(poly);

    out.write((char *) &degree, sizeof(int32_t));
    for (int i = 0; i <= degree; i++) {
        ExportN(out, poly.rep[i]);
    }
}

void ImportN(ifstream &in, ZZX &poly) {
    poly = ZZX::zero();

    int32_t degree;

    in.read((char *) &degree, sizeof(int32_t));
    if (degree == -1) {
        return;
    }

    poly.SetMaxLength(degree + 1);
    for (int i = 0; i <= degree; i++) {
        ZZ coeff;
        ImportN(in, coeff);
        SetCoeff(poly, i, coeff);
    }
}

void ExportN(stringstream &out, const DoubleCRT &poly) {
    IndexMap<vec_long> map = poly.getMap();
    long size = map.getIndexSet().card();
    ExportN(out, size);
    for (long i = map.first(); i <= map.last(); i = map.next(i)) {
        ExportN(out, i);
        ExportN(out, map[i]);
    }
}

void ImportN(ifstream &in, DoubleCRT &poly) {
    IndexMap<vec_long> map;

    uint32_t size;
    ImportN(in, size);

    for (unsigned i = 0; i < size; i++) {
        long key;
        ImportN(in, key);
        map.insert(key);
        ImportN(in, map[key]);
    }

    poly.setMap(map);
}

void ExportN(stringstream &out, const vec_long &vec) {
    uint32_t len = vec.length();
    ExportN(out, len);
    for (int i = 0; i < vec.length(); i++) {
        ExportN(out, vec[i]);
    }
}

void ImportN(ifstream &in, vec_long &vec) {
    uint32_t size;
    ImportN(in, size);
    vec.SetLength(size);

    for (uint32_t i = 0; i < size; i++) {
        ImportN(in, vec[i]);
    }
}

void ExportN(stringstream &out, const CiphertextPart &part) {
    ExportN(out, part.poly);
}

void ImportN(ifstream &in, CiphertextPart &part) {
    ImportN(in, part.poly);
}

void ExportN(stringstream &out, const Ciphertext &ctxt) {
    Ciphertext copy = ctxt;

    copy.ScaleDown();
    ExportN(out, copy.parts);
}

void ImportN(ifstream &in, Ciphertext &ctxt) {
    ctxt.Clear();
    ImportN(in, ctxt.parts);
}