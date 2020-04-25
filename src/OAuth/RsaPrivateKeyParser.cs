using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace MSiccDev.Security.OAuth10
{
    public static class RsaPrivateKeyParser
    {
        #region Private Fields

        private const string InvalidFormatMessage = "Private key has invalid format.";
        private const string PemFooter = "-----END RSA PRIVATE KEY-----";
        private const string PemHeader = "-----BEGIN RSA PRIVATE KEY-----";
        private static readonly string PemBodyPattern = $"^{PemHeader}(.+){PemFooter}$";

        #endregion Private Fields

        #region Private Methods

        private static RSAParameters CreateRsaParameters(BinaryReader br)
        {
            var modulus = ReadRsaParameter(br);
            var exponent = ReadRsaParameter(br);
            var d = ReadRsaParameter(br);
            var p = ReadRsaParameter(br);
            var q = ReadRsaParameter(br);
            var dp = ReadRsaParameter(br);
            var dq = ReadRsaParameter(br);
            var inverseQ = ReadRsaParameter(br);
            return new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent,
                D = d,
                P = p,
                Q = q,
                DP = dp,
                DQ = dq,
                InverseQ = inverseQ
            };
        }

        private static int GetIntegerSize(BinaryReader br)
        {
            int count;
            var bt = br.ReadByte();
            if (bt != 0x02) // expect integer
                throw new InvalidOperationException(InvalidFormatMessage);
            bt = br.ReadByte();
            if (bt == 0x81)
            {
                count = br.ReadByte(); // data size in next byte
            }
            else if (bt == 0x82)
            {
                var highbyte = br.ReadByte();
                var lowbyte = br.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt; // we already have the data size
            }
            while (br.ReadByte() == 0x00)
            {   // remove high order zeros in data
                count -= 1;
            }
            br.BaseStream.Seek(-1, SeekOrigin.Current); // last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        private static byte[] ParseOpenSslPrivateKeyBytes(string pemContent)
        {
            return Convert.FromBase64String(ParsePemBody(pemContent));
        }

        private static string ParsePemBody(string pemContent)
        {
            var result = Regex.Match(pemContent.Trim(), PemBodyPattern, RegexOptions.Compiled | RegexOptions.Singleline);
            if (!result.Success)
                throw new InvalidOperationException("The given key is not pem private key.");
            return result.Groups[1].Value;
        }

        private static RSAParameters ParseRsaParameters(byte[] privateKey)
        {
            using (var ms = new MemoryStream(privateKey))
            using (var br = new BinaryReader(ms))
            {
                ReadPrivateKeyHeader(br);
                return CreateRsaParameters(br);
            }
        }

        private static void ReadPrivateKeyHeader(BinaryReader br)
        {
            var twoBytes = br.ReadUInt16();
            if (twoBytes == 0x8130) // data read as little endian order (actual data order for Sequence is 30 81)
                br.ReadByte(); // advance 1 byte
            else if (twoBytes == 0x8230)
                br.ReadInt16(); // advance 2 bytes
            else
                throw new InvalidOperationException(InvalidFormatMessage);
            var versionNumber = br.ReadUInt16();
            if (versionNumber != 0x0102)
                throw new InvalidOperationException(InvalidFormatMessage);
            if (br.ReadByte() != 0x00)
                throw new InvalidOperationException(InvalidFormatMessage);
        }

        private static byte[] ReadRsaParameter(BinaryReader br)
        {
            return br.ReadBytes(GetIntegerSize(br));
        }

        #endregion Private Methods

        #region Public Methods

        public static RSAParameters ParsePem(string pemContent)
        {
            var privateKey = ParseOpenSslPrivateKeyBytes(pemContent);
            return ParseRsaParameters(privateKey);
        }

        #endregion Public Methods
    }
}