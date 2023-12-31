/*
 
Copyright (c) 2022 Ahmed Kh. Zamil

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


using Esiur.Labs.DSP;
using Esiur.Labs.Fuzzy;
using Esiur.Labs.Optimization;
using Esiur.Labs.Signals;
using Esiur.Labs.Units;
using Microsoft.VisualBasic.Logging;
using ScottPlot;
using ScottPlot.Drawing.Colormaps;
using System.Security.Cryptography;
using Esiur.Labs.Statistics;
using System.Diagnostics;

namespace Esiur.Analysis.Test
{
    public partial class FSoft : Form
    {

        private double[] num = new double[] { 10 };
        private double[] denum = new double[] { 1, 1, 0.1 };
        private int interval = 8000;
        private double stability = 100;

        public FSoft()
        {
            InitializeComponent();

            //var outage = Capacity.ComputeOutage(20000000, new Capacity.CSI[]
            //{
            //    new Capacity.CSI(PowerUnit.FromDb(20), 0.1),
            //    new Capacity.CSI(PowerUnit.FromDb(15), 0.15),
            //    new Capacity.CSI(PowerUnit.FromDb(10), 0.25),
            //    new Capacity.CSI(PowerUnit.FromDb(5), 0.25),
            //    new Capacity.CSI(PowerUnit.FromDb(0), 0.15),
            //    new Capacity.CSI(PowerUnit.FromDb(-5), 0.1),
            //});
            var outage = Capacity.ComputeOutage(1, new Capacity.CSI[]
            {
                new Capacity.CSI(PowerUnit.FromDb(30), 0.2),
                new Capacity.CSI(PowerUnit.FromDb(20), 0.3),
                new Capacity.CSI(PowerUnit.FromDb(10), 0.3),
                new Capacity.CSI(PowerUnit.FromDb(0), 0.2),
             });


            var low = new ContinuousSet(MembershipFunctions.Descending(20, 40));
            var mid = new ContinuousSet(MembershipFunctions.Triangular(20, 40, 60));
            var high = new ContinuousSet(MembershipFunctions.Ascending(40, 60));

            var bad = new ContinuousSet(MembershipFunctions.Descending(0, 30));
            var ok = new ContinuousSet(MembershipFunctions.Triangular(20, 50, 80));
            var excelent = new ContinuousSet(MembershipFunctions.Ascending(70, 100));

            var small = new ContinuousSet(MembershipFunctions.Descending(100, 200));
            var avg = new ContinuousSet(MembershipFunctions.Triangular(100, 200, 300));
            var big = new ContinuousSet(MembershipFunctions.Ascending(200, 300));

            //var speedIsLowThenSmall = new FuzzyRule("Low=>Small", low, small);

            double rating = 80;

            for (double temp = 60; temp < 100; temp++)
            {
                var v = MamdaniDefuzzifier.Evaluate(new INumericalSet<double>[]
                {
                temp.Is(low).And(rating.Is(bad)).Then(small),
                temp.Is(mid).And(rating.Is(ok)).Then(avg),
                temp.Is(high).And(rating.Is(excelent)).Then(big),
                }, MamdaniDefuzzifierMethod.CenterOfGravity, 100, 300, 1);

            }

        }

        private void FMain_Load(object sender, EventArgs e)
        {
            button3_Click(sender, e);
        }


        struct KK
        {
            public float Ki;
            public float Kp;
            public float Kd;

            public override string ToString()
            {
                return $"Ki {Ki} Kp {Kp} Kd {Kd}";
            }
        }

        struct FuzzyChromosome
        {
            ////public sbyte KiInputErrPosition;
            //public sbyte KiInputErrScale;

            ////public sbyte KiInputErrAccPosition;
            //public sbyte KiInputErrAccScale;

            ////public sbyte KiOutputPosition;
            //public sbyte KiOutputScale;

            public sbyte KiStart;
            public byte KiLength;
            public sbyte KdStart;
            public byte KdLength;
            public sbyte KpStart;
            public byte KpLength;

            public override string ToString()
            {
                return $"Ki {KiStart}:{KiLength} Kp {KpStart}:{KpLength} Kd {KdStart}:{KdLength}";
            }
        }

        private double CalculateFuzzyPIDStepError(FuzzyChromosome config, double errStart, double errEnd, double errAccStart, double errAccEnd, bool draw, string label)
        {

            var lowErr = new ContinuousSet(MembershipFunctions.Descending(errStart, errStart + (errEnd - errStart) * 0.5));
            var midErr = new ContinuousSet(MembershipFunctions.Triangular(errStart, errStart + (errEnd - errStart) * 0.5, errEnd));
            var highErr = new ContinuousSet(MembershipFunctions.Ascending(errStart + (errEnd - errStart) * 0.5, errEnd));

            var lowAccErr = new ContinuousSet(MembershipFunctions.Descending(errAccStart, errAccStart + (errAccEnd - errAccStart) * 0.5));
            var midAccErr = new ContinuousSet(MembershipFunctions.Triangular(errAccStart, errAccStart + (errAccEnd - errAccStart) * 0.5, errAccEnd));
            var highAccErr = new ContinuousSet(MembershipFunctions.Ascending(errAccStart + (errAccEnd - errAccStart) * 0.5, errAccEnd));


            var kiSmall = new ContinuousSet(MembershipFunctions.Descending(config.KiStart * 0.1, (config.KiStart + (config.KiLength * 0.5)) * 0.1));
            var kiAvg = new ContinuousSet(MembershipFunctions.Triangular(config.KiStart * 0.1, (config.KiStart + (config.KiLength * 0.5)) * 0.1, (config.KiStart + config.KiLength) * 0.1));
            var kiBig = new ContinuousSet(MembershipFunctions.Ascending((config.KiStart + (config.KiLength * 0.5)) * 0.1, (config.KiStart + config.KiLength) * 0.1));

            var kdSmall = new ContinuousSet(MembershipFunctions.Descending(config.KdStart * 0.1, (config.KdStart + (config.KdLength * 0.5)) * 0.1));
            var kdAvg = new ContinuousSet(MembershipFunctions.Triangular(config.KdStart * 0.1, (config.KdStart + (config.KdLength * 0.5)) * 0.1, (config.KdStart + config.KdLength) * 0.1));
            var kdBig = new ContinuousSet(MembershipFunctions.Ascending((config.KdStart + (config.KdLength * 0.5)) * 0.1, (config.KdStart + config.KdLength) * 0.1));

            var kpSmall = new ContinuousSet(MembershipFunctions.Descending(config.KpStart * 0.1, (config.KpStart + (config.KpLength * 0.5)) * 0.1));
            var kpAvg = new ContinuousSet(MembershipFunctions.Triangular(config.KpStart * 0.1, (config.KpStart + (config.KpLength * 0.5)) * 0.1, (config.KpStart + config.KpLength) * 0.1));
            var kpBig = new ContinuousSet(MembershipFunctions.Ascending((config.KpStart + (config.KpLength * 0.5)) * 0.1, (config.KpStart + config.KpLength) * 0.1));


            double Ki = -1.9181372, Kp = 18.625, Kd = 0.38281253;
            //double Ki = 1, Kp = 1, Kd = 1;

            var step = Enumerable.Repeat(1, interval).Select(x => (double)x).ToArray();
            step[0] = 0;

            var motor = new TransferFunction(num, denum, 0.01);

            var fuzzyPID = new TransferFunction(new double[] { Kd, Kp, Ki }, new double[] { 1, 1 }, 0.01);

            var sysOutFuzzyPID = new double[step.Length];


            var pidOutFuzzy = new double[step.Length];

            var errorOutFuzzy = new double[step.Length];
            var errorOutAccFuzzy = new double[step.Length];

            for (var i = 0; i < step.Length; i++)
            {
                sysOutFuzzyPID[i] = motor.Evaluate(step[i] + (i == 0 ? 0 : pidOutFuzzy[i - 1]));
 

                errorOutFuzzy[i] = (stability - sysOutFuzzyPID[i]);
                errorOutAccFuzzy[i] = (errorOutFuzzy[i] - (i == 0 ? 0 : errorOutFuzzy[i - 1]));



                var ki = MamdaniDefuzzifier.Evaluate(new INumericalSet<double>[]
                {
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kiSmall),
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kiSmall),
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kiAvg),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kiSmall),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kiAvg),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kiBig),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kiAvg),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kiBig),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kiBig),
                }, MamdaniDefuzzifierMethod.CenterOfGravity, config.KiStart  * 0.1, (config.KiStart + config.KiLength) * 0.1, 0.5);

                if (double.IsNaN(ki))
                    return double.MaxValue;

                var kp = MamdaniDefuzzifier.Evaluate(new INumericalSet<double>[]
                 {
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kpSmall),
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kpSmall),
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kpAvg),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kpSmall),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kpAvg),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kpBig),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kpAvg),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kpBig),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kpBig),
                    }, MamdaniDefuzzifierMethod.CenterOfGravity, config.KpStart * 0.1, (config.KpStart + config.KpLength) * 0.1, 0.5);

                if (double.IsNaN(kp))
                    return double.MaxValue;

                var kd = MamdaniDefuzzifier.Evaluate(new INumericalSet<double>[]
                {
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kdSmall),
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kdSmall),
                    errorOutFuzzy[i].Is(lowErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kdAvg),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kdSmall),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kdAvg),
                    errorOutFuzzy[i].Is(midErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kdBig),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(lowAccErr)).Then(kdAvg),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(midAccErr)).Then(kdBig),
                    errorOutFuzzy[i].Is(highErr).And(errorOutAccFuzzy[i].Is(highAccErr)).Then(kdBig),
                }, MamdaniDefuzzifierMethod.CenterOfGravity, config.KdStart * 0.1, (config.KdStart + config.KdLength) * 0.1, 0.5);

                if (double.IsNaN(kd))
                    return double.MaxValue;

                fuzzyPID.InputCoefficients[0] = ki;
                fuzzyPID.InputCoefficients[1] = kp;
                fuzzyPID.InputCoefficients[1] = kd;

                pidOutFuzzy[i] = fuzzyPID.Evaluate(errorOutFuzzy[i]);

            }

            if (draw)
            {
                formsPlot1.Plot.Clear();
                var x = Enumerable.Range(0, interval).Select(x => x * 0.01).ToArray();

                formsPlot1.Plot.AddScatter(x, sysOutFuzzyPID, Color.Green);

                formsPlot1.Plot.AddText(label, 0, 1.5, 24, Color.DarkOrange);

                formsPlot1.Refresh();

                formsPlot2.Plot.Clear();
                var range = FuzzyExtensions.Range(config.KiStart * 0.1, (config.KiStart + config.KiLength) * 0.1, 0.1);

                formsPlot2.Plot.AddScatter(range, kiSmall.Sample(range));
                formsPlot2.Plot.AddScatter(range, kiAvg.Sample(range));
                formsPlot2.Plot.AddScatter(range, kiBig.Sample(range));
                //formsPlot2.Plot.AddText("Ki", 0, 0, 20);

                formsPlot2.Refresh();

                formsPlot3.Plot.Clear();

                range = FuzzyExtensions.Range(config.KpStart * 0.1, (config.KpStart + config.KpLength) * 0.1, 0.1);

                formsPlot3.Plot.AddScatter(range, kpSmall.Sample(range));
                formsPlot3.Plot.AddScatter(range, kpAvg.Sample(range));
                formsPlot3.Plot.AddScatter(range, kpBig.Sample(range));
                //formsPlot2.Plot.AddText("Kp", 0, 0, 20);

                formsPlot3.Refresh();

                formsPlot4.Plot.Clear();

                range = FuzzyExtensions.Range(config.KdStart * 0.1, (config.KdStart + config.KdLength) * 0.1, 0.1);

                formsPlot4.Plot.AddScatter(range, kdSmall.Sample(range));
                formsPlot4.Plot.AddScatter(range, kdAvg.Sample(range));
                formsPlot4.Plot.AddScatter(range, kdBig.Sample(range));
                //formsPlot2.Plot.AddText("Kd", 0, 0, 20);

                formsPlot4.Refresh();


            }

            //Debug.WriteLine("ERR " + errorOutFuzzy.Max() + " " + errorOutFuzzy.Min());
            var r = errorOutFuzzy.Sum(x => Math.Abs((decimal)x));// .RMS();
            //if (decimal.IsNaN(r) || decimal.IsInfinity(r))
            //    Console.WriteLine();

            return (double) r;

        }

        private double CalculatePIDStepError(double Kd, double Kp, double Ki, bool draw, string label)
        {
            var step = Enumerable.Repeat(1, interval).Select(x => (double)x).ToArray();
            step[0] = 0;

            var motor = new TransferFunction(num, denum, 0.01);

            var sysOutPID = new double[step.Length];

            var pidOut = new double[step.Length];
            var errorOutPID = new double[step.Length];
            var pid = new TransferFunction(new double[] { Kd, Kp, Ki }, new double[] { 1, 1 }, 0.01);

            for (var i = 0; i < step.Length; i++)
            {
                sysOutPID[i] = motor.Evaluate(step[i] + (i == 0 ? 0 : pidOut[i - 1]));

                if (double.IsInfinity(sysOutPID[i]))
                    Console.WriteLine();

                errorOutPID[i] = (stability - sysOutPID[i]);

                if (double.IsNaN(errorOutPID[i]))
                    Console.WriteLine();

                pidOut[i] = pid.Evaluate(errorOutPID[i]);

                if (double.IsInfinity(pidOut[i]))
                    Console.WriteLine();



            }

         
            if (draw)
            {
                formsPlot1.Plot.Clear();
                var x = Enumerable.Range(0, interval).Select(x => x * 0.01).ToArray();
                formsPlot1.Plot.AddText(label, 0, 1.5, 24, Color.DarkOliveGreen);
                formsPlot1.Plot.AddScatter(x, sysOutPID, Color.DeepSkyBlue);
                formsPlot1.Refresh();
            }

            var r = errorOutPID.Sum(x => Math.Abs(x));// .RMS();
            if (double.IsPositiveInfinity(r))
                return double.MaxValue;
            else if (double.IsNegativeInfinity(r))
                return double.MinValue;

            return r;// errorOutPID.RMS();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var genetic = new Genetic<FuzzyChromosome>(100, k =>
            {
                if (float.IsNaN(k.KiStart)
                || float.IsNaN(k.KiLength)
                || float.IsNaN(k.KpStart)
                || float.IsNaN(k.KiLength)
                || float.IsNaN(k.KdStart)
                || float.IsNaN(k.KiLength))
                    return (double.MaxValue);

 
                var r = CalculateFuzzyPIDStepError(k, -(stability / 2), stability / 2, -(stability / 2), stability / 2, false, null);
                //var r = CalculateFuzzyPIDStepError(k, -50, 50, -50, 50, false, null);
                if (double.IsNaN(r))
                    Console.WriteLine();
                return r;
            });


            foreach (var (generation, fitness, k) in genetic.Evaluate(100))
            {
                if (float.IsNaN(k.KiStart)
                || float.IsNaN(k.KiLength)
                || float.IsNaN(k.KpStart)
                || float.IsNaN(k.KiLength)
                || float.IsNaN(k.KdStart)
                || float.IsNaN(k.KiLength))
                    continue;

 
                CalculateFuzzyPIDStepError(k, -(stability / 2), stability / 2, -(stability / 2), stability / 2, true, $"Fuzzy PID: Generation {generation} Fitness {Math.Round( fitness)} {k}");
               // CalculateFuzzyPIDStepError(k, -50, 50, -50, 50, true, $"Fuzzy PID: Generation {generation} Fitness {fitness}\r\n{k}");
            }

            // Console.WriteLine(best);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            var gen = new Genetic<KK>(100, k =>
            {
                if (float.IsNaN(k.Ki) || float.IsNaN(k.Kp) || float.IsNaN(k.Kd))
                    return (double.MaxValue);


                var r = CalculatePIDStepError(k.Kd, k.Kp, k.Ki, false, null);
                if (double.IsNaN(r))
                    Console.WriteLine();
                return r;
            });

            foreach (var (generation, fitness, k) in gen.Evaluate(100))
                CalculatePIDStepError(k.Kd, k.Kp, k.Ki, true, $"PID: Generation {generation} Fitness {Math.Round( fitness)} {k}");

        }

        private void button3_Click(object sender, EventArgs e)
        {

            num = textBox1.Text.Split("/").First().Trim().Split(" ").Select(x=>Convert.ToDouble(x)).ToArray();
            denum = textBox1.Text.Split("/").Last().Trim().Split(" ").Select(x=>Convert.ToDouble(x)).ToArray();
            
            var x = Enumerable.Range(0, interval).Select(x => x * 0.01).ToArray();

            var step = Enumerable.Repeat(1, interval).Select(x => (double)x).ToArray();
            step[0] = 0;

            var motor = new TransferFunction(num, denum, 0.01);
 
            var sysOut = new double[step.Length];
 
            var errOut = new double[step.Length];
            var errAccOut = new double[step.Length];

 
            for (var i = 0; i < step.Length; i++)
            {
                sysOut[i] = motor.Evaluate(step[i]);
                errOut[i] = stability - sysOut[i];
                errAccOut[i] = errOut[i] - (i == 0 ? 0 : errOut[i - 1]);

  

            }

            Debug.WriteLine($"Error Values Min: {errOut.Min()} Max: {errOut.Max()} ");
            Debug.WriteLine($"Error Acc Values Min: {errAccOut.Min()} Max: {errAccOut.Max()} ");

            formsPlot1.Plot.AddScatter(x, sysOut, Color.Red);
 
            formsPlot1.Refresh();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            formsPlot1.Plot.Clear();
            formsPlot1.Refresh();
        }

        private void formsPlot1_Load(object sender, EventArgs e)
        {

        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            double s;
            if (double.TryParse(textBox2.Text, out s))
                stability = s;
        }
    }
}