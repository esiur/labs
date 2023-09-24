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
using System.Diagnostics;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using Esiur.Data;

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
            {0, 36, 3, 41, 18 },
            {1, 44, 10, 45, 2 },
            {62, 6, 43, 15, 61 },
            {28, 55, 25, 21, 56 },
            {27, 20, 39, 8, 14 }
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
        int _outputLength; // the output will be trimmed to this length (in bits)

        byte _d; // delimiter


        public Keccak(KeccakPermutation permutation, int rateLength, int capacityLength, int outputLength, bool[] mbits)
        {
            _b = (int)permutation;
            _r = rateLength;
            _c = capacityLength;
            _w = (_b) / 25;
            _l = (int)(Math.Log(_w) / Math.Log(2));
            _n_r = 12 + 2 * _l;

            _outputLength = outputLength;

            _d = (byte)Math.Pow(2, mbits.Length);
            for (var i = 0; i < mbits.Length; i++)
                if (mbits[i])
                    _d += (byte)Math.Pow(2, i);
        }

        public Keccak(KeccakPermutation permutation, int rateLength, int capacityLength, int outputLength, byte delimiter)
        {
            _b = (int)permutation;
            _r = rateLength;
            _c = capacityLength;
            _w = (_b) / 25;
            _l = (int)(Math.Log(_w) / Math.Log(2));
            _n_r = 12 + 2 * _l;

            _outputLength = outputLength;
            _d = delimiter;
        }

        public byte[] Compute(byte[] mbytes)
        {


            /*
                # Padding
                d = 2 ^| Mbits | +sum for i = 0.. | Mbits | -1 of 2 ^ i * Mbits[i]
                P = Mbytes || d || 0x00 || … || 0x00
                P = P xor(0x00 || … || 0x00 || 0x80)
            */

            byte[] p; // padded message

            var rateBytes = (uint)(_r / 8);

            p = new byte[mbytes.Length + (rateBytes - (mbytes.Length % rateBytes))];
            Buffer.BlockCopy(mbytes, 0, p, 0, mbytes.Length);
            // set delimiter
            p[mbytes.Length] = _d;
            // everything between is 0
            // set trailing 1 (pad10*1)
            p[p.Length - 1] |= 0x80;


            if (_w == 64)
            {
                var state = new ulong[5, 5];

                for (uint i = 0; i < p.Length; i += rateBytes)
                {

                    var pi = new ulong[rateBytes / 8];
                    for (uint j = 0; j < pi.Length; j++)
                        pi[j] = p.GetUInt64(i + 8 * j, Endian.Little);


                    for (var x = 0; x < 5; x++)
                        for (var y = 0; y < 5; y++)
                            if (x + (5 * y) < pi.Length)
                                state[x, y] ^= pi[x + (5 * y)];

                    state = KeccakF(state);
                }


                /*
                   # Squeezing phase
                    Z = empty string
                    while output is requested
                      Z = Z || S[x,y],                        for (x,y) such that x+5*y < r/w
                      S = Keccak-f[r+c](S)

                    return Z
                */

 
                var outputBlocks = Math.Ceiling((double)_outputLength / (double)_b); // both in bits

                var outputBytes = _outputLength / 8;

                var rt = new List<byte>();

                do
                {
                    for (var x = 0; x < 5; x++)
                    {
                        for (var y = 0; y < 5; y++)
                        {
                            rt.AddRange(DC.ToBytes(state[y, x], Endian.Little));

                            if (rt.Count >= outputBytes)
                                return rt.Take(outputBytes).ToArray();
                        }
                    }

                    if (--outputBlocks == 0)
                        break;

                    state = KeccakF(state);

                } while (true);


                return rt.Take(outputBytes).ToArray();
            }

            else if (_w == 32)
            {
                var state = new uint[5, 5];

                for (uint i = 0; i < p.Length; i += rateBytes)
                {

                    var pi = new uint[rateBytes / 8];
                    for (uint j = 0; j < pi.Length; j++)
                        pi[j] = p.GetUInt32(i + 8 * j, Endian.Little);


                    for (var x = 0; x < 5; x++)
                        for (var y = 0; y < 5; y++)
                            if (x + 5 * y < pi.Length)
                                state[x, y] ^= pi[x + 5 * y];

                    state = KeccakF(state);
                }


                /*
                   # Squeezing phase
                    Z = empty string
                    while output is requested
                      Z = Z || S[x,y],                        for (x,y) such that x+5*y < r/w
                      S = Keccak-f[r+c](S)

                    return Z
                */

 
                var outputBlocks = Math.Ceiling((double)_outputLength / (double)_b); // both in bits

                var outputBytes = _outputLength / 8;

                var rt = new List<byte>();

                do
                {
                    for (var x = 0; x < 5; x++)
                    {
                        for (var y = 0; y < 5; y++)
                        {
                            rt.AddRange(DC.ToBytes(state[y, x], Endian.Little));

                            if (rt.Count >= outputBytes)
                                return rt.Take(outputBytes).ToArray();
                        }
                    }

                    if (--outputBlocks == 0)
                        break;

                    state = KeccakF(state);

                } while (true);


                return rt.Take(outputBytes).ToArray();

            }

            return null;
        }


        public ulong[,] KeccakF(ulong[,] a)
        {
            for (var i = 0; i < _n_r; i++)
            {
                a = Round(a, RC[i]);
            }

            return a;
        }

        public uint[,] KeccakF(uint[,] a)
        {
            for (var i = 0; i < _n_r; i++)
            {
                a = Round(a, RC[i]);
            }

            return a;
        }


        int Mod5(int number)
        {
            var rt = number % 5;
            if (rt < 0) return rt + 5;
            return rt;
        }

        public ulong RotL(ulong value, int shift)
        {
            return value << shift | value >> (64 - shift);
        }

        public ulong RotR(ulong value, int shift)
        {
            return value >> shift | value << (64 - shift);
        }

        public uint RotL(uint value, int shift)
        {
            return value << shift | value >> (32 - shift);
        }

        public uint RotR(uint value, int shift)
        {
            return value >> shift | value << (32 - shift);
        }

        public ushort RotL(ushort value, int shift)
        {
            return (ushort)(value << shift | value >> (16 - shift));
        }

        public ushort RotR(ushort value, int shift)
        {
            return (ushort)(value >> shift | value << (16 - shift));
        }


        public byte RotL(byte value, int shift)
        {
            return (byte)(value << shift | value >> (16 - shift));
        }

        public byte RotR(byte value, int shift)
        {
            return (byte)(value >> shift | value << (16 - shift));
        }


        void PrintState(ulong[,] s)
        {
            var i = 0;

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                {
                    if (i++ % 2 == 0)
                        Debug.WriteLine("");


                    Debug.Write(" " + DC.ToHex(DC.ToBytes(s[y, x], Endian.Little)));
                }

            Debug.WriteLine("");
        }

        void PrintState(uint[,] s)
        {
            var i = 0;

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                {
                    if (i++ % 4 == 0)
                        Debug.WriteLine("");


                    Debug.Write(" " + DC.ToHex(DC.ToBytes(s[y, x], Endian.Little)));
                }

            Debug.WriteLine("");
        }

        public ulong[,] Round(ulong[,] a, ulong rc)
        {
            /*
              # θ step
              C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
              D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
              A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
            */
            // PrintState(a);

            var c = new ulong[5];
            var d = new ulong[5];

            for (var x = 0; x < 5; x++)
                c[x] = a[x, 0] ^ a[x, 1] ^ a[x, 2] ^ a[x, 3] ^ a[x, 4];


            for (var x = 0; x < 5; x++)
                d[x] = c[Mod5(x - 1)] ^ RotL(c[Mod5(x + 1)], 1);

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    a[x, y] = a[x, y] ^ d[x];

            /*
            # ρ and π steps
                B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
            */
            //PrintState(a);

            var b = new ulong[5, 5];

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    b[y, Mod5((2 * x) + (3 * y))] = RotL(a[x, y], R[x, y]);
            /*
              # χ step
              A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
            */


            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    a[x, y] = b[x, y] ^ ((~b[Mod5(x + 1), y]) & b[Mod5(x + 2), y]);


            /*
              # ι step
              A[0,0] = A[0,0] xor RC
             */

            a[0, 0] = a[0, 0] ^ rc;

            //Debug.WriteLine("Round " + roundId);
            //PrintState(a);

            return a;
        }


        public uint[,] Round(uint[,] a, ulong rc)
        {
            /*
              # θ step
              C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
              D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
              A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
            */

            var c = new uint[5];
            var d = new uint[5];

            for (var x = 0; x < 5; x++)
                c[x] = a[x, 0] ^ a[x, 1] ^ a[x, 2] ^ a[x, 3] ^ a[x, 4];


            for (var x = 0; x < 5; x++)
                d[x] = c[Mod5(x - 1)] ^ RotL(c[Mod5(x + 1)], 1);

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    a[x, y] = a[x, y] ^ d[x];

            /*
            # ρ and π steps
                B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
            */

            var b = new uint[5, 5];

            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    b[y, Mod5((2 * x) + (3 * y))] = RotL(a[x, y], R[x, y]);
            /*
              # χ step
              A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
            */


            for (var x = 0; x < 5; x++)
                for (var y = 0; y < 5; y++)
                    a[x, y] = b[x, y] ^ ((~b[Mod5(x + 1), y]) & b[Mod5(x + 2), y]);


            /*
              # ι step
              A[0,0] = A[0,0] xor RC
             */

            a[0, 0] = (uint)(a[0, 0] ^ rc);

            return a;
        }

    }
}
