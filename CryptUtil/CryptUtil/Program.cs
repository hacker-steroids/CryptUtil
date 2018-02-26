using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace CryptUtil {
    internal class Program {
        internal static byte[] iv;

        internal static readonly byte[] Salt =
        {
            0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B, 0xB2, 0x19, 0x2, 0x24, 0x30, 0xA5, 0x78, 0x43, 0x0, 0x3D, 0x56,
            0x44, 0xD2, 0x1E, 0x62, 0xB9, 0xD4, 0xF1, 0x80, 0xE7, 0xE6, 0xC3, 0x39, 0x41
        };

        static void Main(string[] args) {
            try {
                if (args[0] == "-e") {
                    if (File.Exists(args[1])) {
                        byte[] key = new byte[16];

                        new RNGCryptoServiceProvider().GetBytes(key);

                        byte[] read = File.ReadAllBytes(args[1]);
                        byte[] enc = EncryptBytes(read, key, out iv);

                        File.WriteAllBytes(args[1], enc);

                        WriteSuccessLine("Key: \n\t" + GetByteArrayAsIs(key));
                        Console.WriteLine();
                    }
                } else if (args[0] == "-rsa") {
                    Tuple<byte[], string> t = RSAEncrypt(StringToByteArr(args[1]));
                    Console.WriteLine(GetByteArrayAsIs(t.Item1, "rsaEncrypted"));
                    Console.WriteLine("RSA key: " + t.Item2);
                } else if (args[0] == "-sha") {
                    SHA512 sha = SHA512.Create();
                    Console.WriteLine(Convert.ToBase64String(sha.ComputeHash(Encoding.Default.GetBytes(args[1]))));
                }
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }

        internal static void WriteSuccessLine(string text) {
            Console.ResetColor();
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write("+");
            Console.ResetColor();
            Console.WriteLine("] " + text);
        }

        internal static void WriteErrorLine(string text) {
            Console.ResetColor();
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.Write("-");
            Console.ResetColor();
            Console.WriteLine("] " + text);
        }

        internal static Tuple<byte[], string> RSAEncrypt(byte[] b) {
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(4096);
            RSAParameters privKey = csp.ExportParameters(true);
            RSAParameters pubKey = csp.ExportParameters(false);

            string privKeyString;

            StringWriter sw = new StringWriter();
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, privKey);
            privKeyString = sw.ToString();

            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(pubKey);

            byte[] ciph = csp.Encrypt(b, false);

            return new Tuple<byte[], string>(ciph, privKeyString);
        }

        internal static byte[] RSADecrypt(byte[] ciphB, string privateKey) {
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            RSAParameters privKey = new RSAParameters();

            StringReader sr = new StringReader(privateKey);
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));
            privKey = (RSAParameters)xs.Deserialize(sr);

            csp.ImportParameters(privKey);

            return csp.Decrypt(ciphB, false);
        }

        internal static byte[] StringToByteArr(string s) {
            string[] subs = s.Remove(' ').Split(',');
            List<byte> l = new List<byte>(subs.Length);
            foreach (string strByte in subs) {
                Console.WriteLine(strByte);
                Console.WriteLine(strByte.Replace("0x", ""));
                l.Add(Convert.ToByte(strByte.Replace("0x", "")));
            }
            return l.ToArray();
        }

        internal static byte[] ConvertHexStringToByteArray(string hexString) {
            if (hexString.Length % 2 != 0) {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, "The binary key cannot have an odd number of digits: {0}", hexString));
            }

            byte[] HexAsBytes = new byte[hexString.Length / 2];
            for (int index = 0; index < HexAsBytes.Length; index++) {
                string byteValue = hexString.Substring(index * 2, 2);
                HexAsBytes[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return HexAsBytes;
        }

        internal static string GetByteArrayAsIs(byte[] arr) {
            string res = "byte[] arr = new byte[] { ";
            foreach (byte b in arr) {
                string s = "0x" + Convert.ToInt32(b).ToString("X");
                if (b.Equals(arr.Last())) {
                    res += s + " };";
                } else {
                    res += s + ", ";
                }
            }
            return res;
        }

        internal static string GetByteArrayAsIs(byte[] arr, string declName) {
            string res = $"byte[] {declName} = new byte[] {{ ";
            foreach (byte b in arr) {
                string s = "0x" + Convert.ToInt32(b).ToString("X");
                if (b.Equals(arr.Last())) {
                    res += s + " };";
                } else {
                    res += s + ", ";
                }
            }
            return res;
        }

        internal static byte[] GetByteArrayAsIsFromString(string bytes) {
            List<byte> o = new List<byte>();
            foreach (string substr in bytes.Split(',')) {
                o.Add(Convert.ToByte(substr));
            }
            return o.ToArray();
        }

        internal static string ByteArrayToString(byte[] ba) {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba) {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        internal static string ByteToString(byte b) {
            StringBuilder hex = new StringBuilder(2);
            hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        internal static byte[] EncryptBytes(byte[] plain, byte[] Key, out byte[] IV, PaddingMode paddingMode = PaddingMode.None) {
            if ((plain.Length % Key.Length) != 0)
                paddingMode = PaddingMode.PKCS7;
            byte[] encrypted;
            byte[] full;
            using (MemoryStream mstream = new MemoryStream()) {
                using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider()) {
                    aesProvider.KeySize = 128;
                    aesProvider.BlockSize = 128;
                    aesProvider.Mode = CipherMode.CBC;
                    aesProvider.Padding = paddingMode;
                    aesProvider.GenerateIV();
                    IV = aesProvider.IV;
                    aesProvider.Key = Key;
                    using (CryptoStream cryptoStream = new CryptoStream(mstream, aesProvider.CreateEncryptor(), CryptoStreamMode.Write)) {
                        cryptoStream.Write(plain, 0, plain.Length);
                    }
                    encrypted = mstream.ToArray();
                    full = new byte[encrypted.Length + IV.Length];
                    Array.Copy(encrypted, full, encrypted.Length);
                    Array.ConstrainedCopy(IV, 0, full, encrypted.Length, IV.Length);
                }
            }
            return full;
        }

        internal static byte[] DecryptBytes(byte[] encrypted, byte[] Key, PaddingMode paddingMode = PaddingMode.None) {
            try {
                if ((encrypted.Length % Key.Length) != 0)
                    paddingMode = PaddingMode.PKCS7;
                byte[] IV = new byte[16];
                Array.ConstrainedCopy(encrypted, encrypted.Length - 16, IV, 0, 16);
                byte[] plain = new byte[encrypted.Length - IV.Length];
                ArraySegment<byte> segment = new ArraySegment<byte>(encrypted, 0, encrypted.Length - IV.Length);
                using (MemoryStream mStream = new MemoryStream(encrypted)) {
                    using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider()) {
                        aesProvider.KeySize = 128;
                        aesProvider.BlockSize = 128;
                        aesProvider.Mode = CipherMode.CBC;
                        aesProvider.Padding = paddingMode;
                        using (CryptoStream cryptoStream = new CryptoStream(mStream, aesProvider.CreateDecryptor(Key, IV), CryptoStreamMode.Read)) {
                            cryptoStream.Read(segment.Array, 0, encrypted.Length);
                        }
                    }
                }
                return segment.Array;
            } catch (Exception e) {
                Console.Error.WriteLine(e.ToString());
                return new byte[0];
            }
        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        internal static bool AreEqual(byte[] a1, byte[] a2) {
            bool result = true;
            for (int i = 0; i < a1.Length; ++i) {
                if (a1[i] != a2[i])
                    result = false;
            }
            return result;
        }
    }
}