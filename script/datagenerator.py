__author__ = 'george'

import argparse,random


def main():
    parser = argparse.ArgumentParser(description='This program generate data for k-means')
    parser.add_argument('-p',action='store',dest='p', help='Prime number the same as in cryptographic context ')
    parser.add_argument('-d',action='store',dest='d', help='Data points dimension. Always d<phim ')
    parser.add_argument('-n',action='store',dest='n',help='Number of data points')
    parser.add_argument('-f',action='store',dest='f',help='Filename')
    args = parser.parse_args()

    if args.p is not None:
        p = int(args.p)
    else:
        p=23

    if args.d is not None:
        d= int(args.d)
    else:
        d=5

    if args.n is not None:
        n= int(args.n)
    else:
        n=10

    if args.f is not None:
        f=args.f
    else:
        f="sample.dat"

    print(p,d,n,f)

    point = ""
    with open(f,"a") as datafile:
        datafile.write(str(d)+" "+str(n))
        datafile.write("\n")
        for x in range(n):
            for y in range(d+1):
                point+=str(random.randint(0,p-1))
                point+=" "
            datafile.write(point)
            datafile.write("\n")
            point=""
        datafile.close()
if __name__=='__main__':
    main()
