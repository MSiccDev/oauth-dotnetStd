using System;
using System.Security.Cryptography;
using System.Text;

namespace MSiccDev.Security.OAuth10
{
    public static class TextSigner
    {
        #region Public Methods

        public static string SignWithRsaSha1(string text, string pemRsaPrivateKey)
        {
            using (var rsa = RSA.Create())
            using (var sha1 = SHA1.Create())
            {
                var rsaParameters = RsaPrivateKeyParser.ParsePem(pemRsaPrivateKey);
                rsa.ImportParameters(rsaParameters);
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(text));
                var signedHash = rsa.SignHash(hash, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signedHash);
            }
        }

        #endregion Public Methods
    }
}