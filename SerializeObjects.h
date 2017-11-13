//
// Created by george on 11/11/2017.
//

#ifndef KCLIENT_SERIALIZEOBJECTS_H
#define KCLIENT_SERIALIZEOBJECTS_H

#include <NTL/ZZ.h>
#include <sstream>
#include <fstream>
#include "DoubleCRT.h"
#include "Ciphertext.h"
#include "Matrix.h"

void ExportN(ofstream &out, const ZZ &val);
void ExportN(ofstream &out, const ZZX &val);
void ExportN(ofstream &out, const DoubleCRT &val);
void ExportN(ofstream &out, const vec_long &vec);

void ImportN(ifstream &in, ZZ &val);
void ImportN(ifstream &in, ZZX &val);
void ImportN(ifstream &in, DoubleCRT &val);
void ImportN(ifstream &in, vec_long &vec);

void ExportN(ofstream &out, const CiphertextPart &part);
void ExportN(ofstream &out, const Ciphertext &ctxt);

void ImportN(ifstream &in, CiphertextPart &part);
void ImportN(ifstream &in, Ciphertext &ctxt);

template<typename T>
void ExportN(ofstream &out, const T &val) {
    out.write((char *) &val, sizeof(T));
}

template<typename T>
void ImportN(ifstream &in, T &val) {
    in.read((char *) &val, sizeof(T));
}

template<typename T>
void ExportN(ofstream &out, const vector<T> &vec) {
    uint32_t size = vec.size();
    ExportN(out, size);
    for (unsigned i = 0; i < vec.size(); i++) {
        ExportN(out, &vec[i]);
    }
}

template<typename T>
void ImportN(ifstream &in, vector<T> &vec) {
    uint32_t size;
    ImportN(in, size);

    vec.resize(size);
    for (unsigned i = 0; i < size; i++) {
        ImportN(in, vec[i]);
    }
}

template<typename T>
void ExportN(ofstream &out, const Matrix<T> &mat) {
    ExportN(out, mat.NumRows());
    ExportN(out, mat.NumCols());

    for (unsigned i = 0; i < mat.NumRows(); i++) {
        for (unsigned j = 0; j < mat.NumCols(); j++) {
            ExportN(out, mat(i,j));
        }
    }
}

template<typename T>
void ImportN(ifstream &in, Matrix<T> &mat) {
    uint32_t nRows, nCols;
    ImportN(in, nRows);
    ImportN(in, nCols);

    mat.Resize(nRows, nCols);
    for (unsigned i = 0; i < nRows; i++) {
        for (unsigned j = 0; j < nCols; j++) {
            ImportN(in, mat(i,j));
        }
    }
}








#endif //KCLIENT_SERIALIZEOBJECTS_H
