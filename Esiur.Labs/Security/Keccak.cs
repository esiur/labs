/*
MIT License

Copyright (c) 2012 - 2023 Esiur Foundation, Ahmed Khalaf Zamil.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

// reference: https://keccak.team/keccak_specs_summary.html

using System;
using System.Collections.Generic;
using System.Text;

namespace Esiur.Labs.Security
{
    public class Keccak
    {

        // Round constants
        readonly ulong[] RC =
        {
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808A,
            0x8000000080008000,
            0x000000000000808B,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008A,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000A,
            0x000000008000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008
        };

        // Rotation offsets
        readonly int[,] R =
        {
            {0, 1, 62, 28, 27},
            {36, 44, 6, 55, 20},
            {3, 10, 43, 25, 39},
            {41, 45, 15, 21, 8}
        };

        public enum KeccakPermutation
        {
            P25 = 25,
            P50 = 50,
            P100 = 100,
            P200 = 200,
            P400 = 400,
            P800 = 800,
            P1600 = 1600
        }

        //ulong[] state = new ulong[25];// 5x5x64

        //int rate, capacity, width, rounds;

        int _b; // width of permutations (25, 50, 100, 200, 400, 800, 1600)
        int _w; // word size {1, 2, 4, 8, 16, 32, 64}
        int _l; // word size self information ? {0, 1, 2, 3, 4, 5, 6}
        int _r; // rate length
        int _c; // capacity
        int _n_r; // number of rounds
        int _outputLength; // the output will be trimmed to this length

        public Keccak(KeccakPermutation permutation, int rateLength, int capacityLength, int outputLength)//, ulong[] initialState)
        {
            _b = (int)permutation;
            _r = rateLength;
            _c = capacityLength;
            _w = (_b) / 25;
            _l = (int)(Math.Log(_w) / Math.Log(2));
            _n_r = 12 + 2 * _l;

            _outputLength = outputLength;

            //if (rateLength + capacityLength != 200)
            //    throw new Exception("Rate+Capacity must equal to 200.");

            //if (rateLength % 8 != 0) throw new Exception("Rate length is not a multiple of 8.");

            //if (initialState != null)
            //{
            //    if (initialState.Length > 25) throw new Exception("Initial state must be less than 25 words length");

            //    if (initialState[0] == 0) throw new Exception("First word in the initialState can't be empty.");

            //    // copy state
            //    Buffer.BlockCopy(initialState, 0, state, 0, initialState.Length);

            //    // permute
            //}
        }


        public byte[] Compute(bool[] mbits, byte[] mbytes)
        {

            var rt = new byte[_outputLength];

            /*
                # Padding
                d = 2 ^| Mbits | +sum for i = 0.. | Mbits | -1 of 2 ^ i * Mbits[i]
                P = Mbytes || d || 0x00 || … || 0x00
                P = P xor(0x00 || … || 0x00 || 0x80)
            */

            var d = Math.Pow(2, mbits.Length);
            for (var i = 0; i < mbits.Length; i++)
                if (mbits[i])
                    d += Math.Pow(2, i);



            /*
              # Initialization
                S[x, y] = 0,                               for (x, y) in (0…4,0…4)
            */

            ulong[][] S;

            for (var i = 0; i < )

            /*
  # Absorbing phase
  for each block Pi in P
    S[x, y] = S[x, y] xor Pi[x + 5 * y],          for (x, y) such that x + 5 * y < r / w
    S = Keccak - f[r + c](S)
            */

            /*
  # Squeezing phase
  Z = empty string
  while output is requested
    Z = Z || S[x, y],                        for (x, y) such that x + 5 * y < r / w
    S = Keccak - f[r + c](S)
              return Z

             */

            return rt;
        }


        public void KeccakF(ulong[,] a)
        {
            for (var i = 0; i < a.Length; i++)
            {
                Round(a, RC[i]);
            }
        }

        public ulong RotL(ulong value, int shift)
        {
            return value << shift | value >> (64 - shift);
        }

        public ulong RotR(ulong value, int shift)
        {
            return value >> shift | value << (64 - shift);
        }


        public void Round(ulong[,] a, ulong rc)
        {
            /*
              # θ step
              C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
              D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
              A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
            */

            var c = new ulong[5];
            var d = new ulong[5];

            for (var x = 0; x < 5; x++)
                c[x] = a[x, 0] ^ a[x, 1] ^ a[x, 2] ^ a[x, 3] ^ a[x, 4];


            for (var x = 0; x < 5; x++)
                d[x] = c[x - 1] ^ RotL(c[(x + 1)%5], 1);

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    a[x, y] = a[x, y] ^ d[x];

            /*
            # ρ and π steps
                B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
            */

            var b = new ulong[5, 5];

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    b[y, (2 * x + 3 * y) % 5] = RotL(a[x, y], R[x, y]);
            /*
              # χ step
              A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
            */

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    a[x, y] = b[x, y] ^ ((~b[(x + 1) % 5, y]) & b[(x + 2) % 5, y]);

            /*
              # ι step
              A[0,0] = A[0,0] xor RC
             */

            a[0, 0] = a[0, 0] ^ rc;
        }
    }
}
