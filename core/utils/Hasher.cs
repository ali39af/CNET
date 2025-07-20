using System.Security.Cryptography;
using System.Text;

namespace CNET
{
    public static class Hasher
    {
        public static string Sha512(string context)
        {
            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] data = Encoding.UTF8.GetBytes(context);
                byte[] hashBytes = sha512.ComputeHash(data);
                StringBuilder hashHex = new StringBuilder(hashBytes.Length * 2);
                foreach (byte b in hashBytes)
                {
                    hashHex.Append(b.ToString("x2"));
                }
                return hashHex.ToString();
            }
        }
    }
}
