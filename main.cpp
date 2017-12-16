//
// Created by george on 8/11/2017.
//

//#include "KClient.h"
//#include "KClientV1.h"
#include "KClientV2.h"
#include <ctime>
#include <chrono>
#include <iomanip>

int main(){
    clock_t c_start = clock();
    auto t_start = chrono::high_resolution_clock::now();
    unsigned p=23;
    unsigned g=7;
    unsigned logQ=117;
    //KClientV1 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,true);
    KClientV2 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,true);

    //client.sendEncryptedData();
    //client.sendPublicKey("127.0.0.1",5001);
    //client.conn("127.0.0.1",5001);
    //client.sendData("Hello  from Client");
    //std:cout<<client.receive(512)<<std::endl;
    std::clock_t c_end = std::clock();
    auto t_end = std::chrono::high_resolution_clock::now();

    std::cout << fixed << setprecision(2) << "CPU time used: "
              << 1000.0 * (c_end-c_start) / CLOCKS_PER_SEC << " ms\n"
              << "Wall clock time passed: "
              << chrono::duration<double, milli>(t_end-t_start).count()
              << " ms"<<endl;

}