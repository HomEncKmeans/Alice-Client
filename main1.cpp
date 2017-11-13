//
// Created by george on 7/10/2017.
//
#include "helpfunctions.h";
#include "FHE-SI.h"
#include "Util.h"
#include "Ciphertext.h"
int main(){
    //Setup FHE Context
    unsigned p=23;
    unsigned g=7;
    unsigned logQ=117;
    FHEcontext context(p-1,logQ,p,g,3);
    activeContext =&context;
    context.SetUpSIContext();
    print("Cryptographic context:");
    print(context);

    //Load data points as polynomials
    vector<ZZ_pX> loadeddata;
    vector<ZZ_p> labels;
    unsigned dim;
    LoadDataPolyX(loadeddata,labels,dim,"../sample.dat",context);
    print("Data points polynomials:");
    PrintVector(loadeddata);
    std::cout<<"\n"<<std::endl;
    print("Data points labels to ZZ_p:"); //this is for [X|Y] style data points
    PrintVector(labels);

    //Setup Keys
    FHESISecKey fhesiSecKey1(context);
    FHESIPubKey fhesiPubKey1(fhesiSecKey1);
    KeySwitchSI keySwitchSI1(fhesiSecKey1);
    print("First 3-tuple of keys");
    print(fhesiSecKey1);
    print(fhesiPubKey1);
    print(keySwitchSI1);
    /*
    const vector<vector<DoubleCRT>> &rep = keySwitchSI1.GetRepresentation();
    for(unsigned i=0;i<rep.size();i++){
        for(unsigned j=0;j<rep[i].size();j++){print(rep[i][j]);}
        }
    print("---------------");
    */
    print("Second 3-tuple of keys");
    FHESISecKey fhesiSecKey2(context);
    FHESIPubKey fhesiPubKey2(fhesiSecKey2);
    KeySwitchSI keySwitchSI2(fhesiSecKey2);
    print(fhesiSecKey2);
    print(fhesiPubKey2);
    print(keySwitchSI2);

    KeySwitchSI commonkeySwitchSI(fhesiSecKey1,fhesiSecKey2);
    print("The common switch key matrix:");
    print(commonkeySwitchSI);


    print("Proof of Concept:");
    ZZ_pX ptx1poly,ptx2poly,sum,ptx3poly;
    // Simple example of encrypt, sum, decrypt:
    print("The data point loaded as polynomials:");
    ptx1poly=loadeddata[0];
    ptx2poly=loadeddata[1];
    ptx3poly = -1*ptx1poly;
    print(ptx1poly);
    print(ptx2poly);
    sum=ptx1poly+ptx2poly;
    print("The sum of two vectors are:");
    print(sum);
    Plaintext ptx1(context,ptx1poly),ptx2(context,ptx2poly);
    print("The points in plaintext are:");
    print(ptx1);
    print(ptx2);
    Ciphertext cipht1(fhesiPubKey1),cipht2(fhesiPubKey1);
    fhesiPubKey1.Encrypt(cipht1,ptx1);
    fhesiPubKey1.Encrypt(cipht2,ptx2);
    print("The ciphertexts of points 1 and 2 are:");
    print(cipht1);
    print(cipht2);
    Ciphertext csum = cipht1;
    csum+=cipht2;
    print("The encrypted sum is:");
    print(csum);
    Plaintext desum;
    fhesiSecKey1.Decrypt(desum,csum);
    print("Decrypted sum is:");
    print(desum);
    //Change of keys

    commonkeySwitchSI.ApplyKeySwitch(csum);
    print("The encrypted sum after key switch is :");
    print(csum);
    Plaintext switcheddesum;
    fhesiSecKey2.Decrypt(switcheddesum,csum);
    print("The decrypted sum after key switch is:");
    print(switcheddesum);

    //Calculating the distance between two points:
    ZZ_pX distanceH11,distanceH12;
    print("\n");
    print("Manhattan distance calculation");
    print("Using plaintext form...");
    print("The distances between points 1-1 and points 1-2 are:");
    distanceH11=ptx1poly+ptx3poly;
    print(distanceH11);
    print(extraxtHM(distanceH11));
    distanceH12=ptx2poly+ptx3poly;
    print(distanceH12);
    print(extraxtHM(distanceH12));
    print("Using ciphertext form...");
    Plaintext ptHM1(context,ptx1poly),ptHM2(context,ptx2poly),ptHM3(context,ptx3poly),pHM11,pHM12;
    Ciphertext cHM1(fhesiPubKey1),cHM2(fhesiPubKey1),cHM3(fhesiPubKey1);
    Ciphertext cHM11,cHM12;
    fhesiPubKey1.Encrypt(cHM1,ptHM1);
    fhesiPubKey1.Encrypt(cHM2,ptHM2);
    fhesiPubKey1.Encrypt(cHM3,ptHM3);
    cHM11=cHM1;
    cHM11+=cHM3;
    cHM12=cHM2;
    cHM12+=cHM3;
    commonkeySwitchSI.ApplyKeySwitch(cHM11);
    commonkeySwitchSI.ApplyKeySwitch(cHM12);
    fhesiSecKey2.Decrypt(pHM11,cHM11);
    fhesiSecKey2.Decrypt(pHM12,cHM12);
    print("The distances between points 1-1 and points 1-2 are:");
    print(pHM11);
    print(extraxtHM(pHM11.message));
    print(pHM12);
    print(extraxtHM(pHM12.message));
    //savePublicKey(fhesiPubKey1,"pkey.dat");
    //saveSecretKey(fhesiSecKey,"skey.dat");
    //saveSwitchedKey(keySwitchSI1,"switchkey.dat");




    return 0;

}
