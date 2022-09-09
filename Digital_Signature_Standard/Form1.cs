using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace DSS
{
    public partial class Form1 : Form
    {

        public struct SignedMessage
        {
            public SignedMessage(byte[] fileBytes, BigInteger r, BigInteger s)
            {
                FileBytes = fileBytes;
                R = r;
                S = s;
            }
            public byte[] FileBytes { get; set; }
            public BigInteger R { get; set; }

            public BigInteger S { get; set; }
        }

        public BigInteger Hash1;

        public static BigInteger ExtendedEuclid(BigInteger a, BigInteger b)
        {
            bool flag = false;
            if(a < b)
            {
                BigInteger temp = b;
                b = a;
                a = temp;
                flag = true;
            }

            Vector U = new Vector(a, 1, 0);
            Vector V = new Vector(b, 0, 1);
            Vector T = new Vector();

            while(V.v1 != 0)
            {
                BigInteger q = U.v1 / V.v1;
                T.v1 = U.v1 % V.v1;
                T.v2 = U.v2 - q * V.v2;
                T.v3 = U.v3 - q * V.v3;
                U = V;
                V = T;
            }

            if (flag) b = a;

            return U.v3 > 0 ? U.v3 : U.v3 + b;
        }

        public struct Vector
        {
            public Vector(BigInteger v1, BigInteger v2, BigInteger v3)
            {
                this.v1 = v1;
                this.v2 = v2;
                this.v3 = v3;
            }

            public BigInteger v1;

            public BigInteger v2;

            public BigInteger v3;
        }

        public SignedMessage Message { get; set; }
        public byte[] FileBytes { get; set; }
        public static BigInteger p = BigInteger.Parse("89884656743115796742429711405763364460177151692783429800884652449310979263752253529349195459823881715145796498046459238345428121561386626945679753956400077352882071663925459750500807018254028771490434021315691357123734637046894876123496168716251735252662742462099334802433058472377674408598573487858308054417");
        public static BigInteger q = BigInteger.Parse("1193447034984784682329306571139467195163334221569");
        public static BigInteger a;
        public static BigInteger y;

        public Form1()
        {
            InitializeComponent();
        }

        // Creating a signature
        private void button1_Click(object sender, EventArgs e)
        {
            Random rand = new Random();
            BigInteger b = (p - 1) / q;

            BigInteger h = ComputeHash();

            Hash1 = h;

            BigInteger s;
            BigInteger r;

            do
            {
                int g = rand.Next(2, 2000000000);
                a = BigInteger.ModPow(g, b, p);
            }
            while (a == 1);

            int x = rand.Next(1, 2000000000);
            y = BigInteger.ModPow(a, x, p); 

            do
            {
                int k;
                do
                {
                    k = rand.Next(1, int.MaxValue);
                    r = BigInteger.ModPow(BigInteger.ModPow(a, k, p), 1, q);
                }
                while (r == 0); 
                s = BigInteger.ModPow(ExtendedEuclid(k, q) * (h + x * r), 1, q);
            }
            while (s == 0); 
            Message = new SignedMessage(FileBytes, r, s);
            button3.Enabled = true;
            MessageBox.Show("Electronic signature created succesfully.");
        }

        // Selecting a file
        private void button2_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.Cancel)
            {
                return;
            }
            FileBytes = File.ReadAllBytes(openFileDialog1.FileName);
            MessageBox.Show("File loaded succesfully!");
            button1.Enabled = true;
        }

        // Verifying a signature
        private void button3_Click(object sender, EventArgs e)
        {
            BigInteger h = ComputeHash();
            if(Message.R < 0 || Message.R > q || Message.S < 0 || Message.S > q)
            {
                MessageBox.Show("Wrong signature!");
                return;
            }

            BigInteger sminusone = ExtendedEuclid(Message.S, q);
            BigInteger u1 = (h * sminusone) % q;
            BigInteger u2 = (Message.R * sminusone) % q;

            BigInteger v = ((BigInteger.ModPow(a, u1, p) * BigInteger.ModPow(y, u2, p)) % p) % q;

            if (v == Message.R)
            {
                MessageBox.Show("Подпись подходит!");
                if ((Message.S * sminusone) % q == 1)
                {
                    MessageBox.Show("True."); 
                }
            }
            else
            {
                MessageBox.Show("Wrong signature!");
            }
        }

        // Using hash-algorithm SHA-1
        public BigInteger ComputeHash()
        {
            SHA1 sha = SHA1.Create();
            byte[] hash = sha.ComputeHash(FileBytes);
            return new BigInteger(hash);
        }

    }
}
