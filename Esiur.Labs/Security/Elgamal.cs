using System;
using System.Collections.Generic;
using System.Text;

namespace Esiur.Labs.Security
{
    public class Elgamal
    {
        int g, p;
        int pri, pub;

        public int PrivateKey => pri;
        public int PublicKey => pub;

        public Elgamal(int root, int modulo)
        {
            g = root; // primitive root
            p = modulo; // prime
            var r = new Random();
            pri = r.Next(2, p - 1);
            pub = (int)Math.Pow(g, pri) % p;
        }

        public (int, int) Encrypt(int peerPublicKey, int msg)
        {
            // session key
            var s = (int)Math.Pow(peerPublicKey, pri) % p;

            var c = (s * msg) % p;

            return (pub, c);
        }

        public int Decrypt(int peerPublicKey, int c)
        {
            // session key
            var s = (int)Math.Pow(peerPublicKey, pri) % p;

            var multiplicativeInverseS = FindMultiplicativeInverse(s, p);
            var m = (multiplicativeInverseS * c) % p;

            return m;
        }

        public int FindMultiplicativeInverse(int num, int p)
        {
            // A number to multiply by another mod prime = 1
            for(var i = 1; i< p; i++)
                if ((i * num) % p == 1) return i;

            throw new Exception("Can't find an inverse, make sure 'p' is a prime number.");
        }
    }
}
