using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.WebSockets;
using System.Text;

namespace Esiur.Labs.Security
{
    public class DiffieHellman
    {

        int g, p;
        int pri, pub;

        public int PrivateKey => pri;
        public int PublicKey => pub;
        
        public DiffieHellman(int root, int modulo)
        {
            g = root; // primitive root
            p = modulo; // prime
            var r = new Random();
            pri = r.Next(2, p-1);
            pub = (int)Math.Pow(g, pri) % p;
        }

        public int GetSessionKey(int peerPublicKey)
        {
            return (int)Math.Pow(peerPublicKey, pri) % p;
        }
        
    }
}
