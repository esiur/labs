using System;
using System.Collections.Generic;
using System.Text;

namespace Esiur.Labs.Neural
{
    internal class Synapse
    {
        public double Weight { get; set; }

        public Neuron Source { get; set; }
        public Neuron Target { get; set; }
    }
}
