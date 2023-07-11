using System;
using System.Collections.Generic;
using System.Text;

namespace Esiur.Labs.Fuzzy
{
    public interface INumericalSet<T>
    {
        public T this[T index] { get; }
        public double AlphaCut { get; set; }

        public INumericalSet<T> Intersection(INumericalSet<T> with);
        public INumericalSet<T> Union(INumericalSet<T> with);

    }
}
