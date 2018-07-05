//
// Created by george on 8/11/2017.
//

//#include "KClientT1V1.h"
//#include "KClientT1V2.h"
//#include "KClientT1V3.h"
#include "KClientT2V1.h"
//#include "KClientT2V2.h"
//#include "KClientT2V3.h"

#include <ctime>
#include <chrono>
#include <iomanip>

int main(){
    string version="T2V3";
    string dataset="1";
    string unit="KClient";
    double cpu_time;
    double wall_clock;

    clock_t c_start = clock();
    auto t_start = chrono::high_resolution_clock::now();
    unsigned p= 2027;//1487;//1487
    unsigned g=7;
    unsigned logQ=55; //4
    //KClientT1V1 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,3);
    //KClientT1V2 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,3, true);
    //KClientT1V3 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,3, true);
    KClientT2V1 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,3,true);
    //KClientT2V2 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,3,true);
    //KClientT2V3 client(p,g,logQ,"../sample.dat","127.0.0.1",5001,"127.0.0.1",5002,3,true);


    std::clock_t c_end = std::clock();
    auto t_end = std::chrono::high_resolution_clock::now();
    cpu_time=1000.0 * (c_end-c_start) / CLOCKS_PER_SEC;
    wall_clock=chrono::duration<double, milli>(t_end-t_start).count();
    std::cout << fixed << setprecision(2) << "CPU time used: "
              << cpu_time << " ms\n"
              << "Wall clock time passed: "
              << wall_clock
              << " ms"<<endl;
    string result= unit+","+version+","+dataset+","+to_string(cpu_time)+","+to_string(wall_clock)+"\n";
    ofstream myfile;
    myfile.open ("exp_"+unit+"_"+version+"_"+dataset+".csv");
    myfile << result;
    myfile.close();
    return 0;

}