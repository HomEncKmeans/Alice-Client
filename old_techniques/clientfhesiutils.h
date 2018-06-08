//
// Created by George Sakellariou on 29/09/2017.
//

#ifndef KCLIENT_CLIENTFHESIUTILS_H
#define KCLIENT_CLIENTFHESIUTILS_H

#include <string>
#include "FHEContext.h"
#include "Matrix.h"
#include <string>
#include <iostream>
#include <fstream>
#include "FHE-SI.h"
#include <bitset>
#include "ZZ_pX.h"
#include "Ciphertext.h"
#include "chrono"
#include "ctime"
#include "iomanip"
bool LoadDataPolyX(vector<ZZ_pX> &rawData, vector<ZZ_p> &labels, unsigned &dim, const string &filename, FHEcontext &context);
bool LoadDataVecPolyX(vector<vector<ZZ_pX>> &rawData, vector<ZZ_p> &labels, unsigned &dim, const string &filename,
                      FHEcontext &context,vector<vector<uint32_t >> &rawDatatoInt);
void timeCalulator(const clock_t &c_start, const chrono::high_resolution_clock::time_point &t_start);
long combine(long a, long b);


template <typename T>
void print(const T &message){
    std::cout<<message<<std::endl;
}


#endif //KCLIENT_CLIENTFHESIUTILS_H
