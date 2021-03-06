/* Copyright (C) 2012,2013 IBM Corp.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
 
#ifndef _PAlgebra_H_
#define _PAlgebra_H_
/* PAlgebra.h - Declatations of the classes PAlgebra, PAlgebra2, PAlgebra2r
 *
 * The class PAlgebra is the base class containing the structure of (Z/mZ)^*,
 * which is isomorphic to the Galois group over A = Z[X]/Phi_m(X)). The
 * derived classes PAlgebra2 and PAlgebra2r contain also the structure of
 * the plaintext spaces A_2 = A/2A and A_2r = A/(2^r A), namely polynomials
 * over Z/2Z and polynomials over Z/2^r Z. 
 *
 * We representat (Z/mZ)^* as (Z/mZ)^* = <2> x <g1,g2,...> x <h1,h2,...>
 * where the group generated by g1,g2,... consists of the elements that
 * have the same order in (Z/mZ)^* as in (Z/mZ)^* /<2>, and h1,h2,...
 * generate the remaining quotient group (Z/mZ)^* /<2,g1,g2,...>. 
 * 
 * We let T \subset (Z/mZ)^* be a set of representatives for the quotient
 * group (Z/mZ)^* /<2>, defined as T={ \prod_i gi^{ei}\cdot\prod_j hj^{ej} }
 * where the ei's range over 0,1,...,ord(gi)-1 and the ej's range over
 * 0,1,...ord(hj)-1 (these last orders are in (Z/mZ)^* /<2,g1,g2,...>).
 *
 * Phi_m(X) is factored as Phi_m(X)=\prod_{t\in T} F_t(X) mod 2 (or mod 2^r),
 * where the F_t's are irreducible modulo 2 (or 2^r). An arbitrarily factor
 * is chosen as F_1, then for each t \in T we associate with the index t the
 * factor F_t(X) = GCD(F_1(X^t), Phi_m(X)).
 *
 * Note that fixing a representation of the field R=(Z/2Z)[X]/F_1(X) (or
 * ring R=(Z/2^rZ)[X]/F_1(X)) and letting z be a root of F_1 in R (which
 * is a primitive m-th root of unity in R), we get that F_t is the minimal
 * polynomial of z^{1/t}.
 */
#include <vector>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>
#include <NTL/vec_GF2.h>

NTL_CLIENT
class PAlgebra {
  unsigned m;        // the integer m defines (Z/mZ)^*, Phi_m(X), etc.
  unsigned g;        // generator for the cyclic group (Z/mZ)^*
  unsigned phim;     // phi(m)

  ZZX Phi_mX;  // Holds the integer polynomial Phi_m(X)
  double cM;   // the ring constant c_m for Z[X]/Phi_m(X)

  vector<long> zmsIdx; // if t is the i'th element in (Z/mZ)* then zmsIdx[t]=i
                       // zmsIdx[t]==-1 if t\notin (Z/mZ)*

 public:
  void init(unsigned mm, unsigned g); // compute the structure of (Z/mZ)^*

  // Constructors
  PAlgebra(unsigned mm=0,unsigned g=0) : m(0) { init(mm,g); }

  // I/O methods

  void printout() const;  // prints the structure in a readable form

  // Access methods

  unsigned M() const { return m; }
  unsigned G() const { return g; }
  unsigned phiM() const { return phim; }
  const ZZX& PhimX() const { return Phi_mX; }


  int indexInZmstar(unsigned t) const   // returns the index of t in (Z/mZ)*
  {  return (t>0 && t<m)? zmsIdx[t]: -1; }

  bool inZmStar(unsigned t) const    // is t\in[0,m-1], (t,m)=1?
  {  return (t>0 && t<m && zmsIdx[t]>-1); }

};

#endif // #ifdef _PAlgebra_H_
