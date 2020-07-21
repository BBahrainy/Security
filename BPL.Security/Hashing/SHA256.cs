using System;
using System.Collections.Generic;
using System.Text;

namespace BPL.Security.Hashing
{
    public static class SHA256
    {
        public static string ComputeHash(string input)
        {
            // Create a SHA256   
            using (System.Security.Cryptography.SHA256 sha256Hash = System.Security.Cryptography.SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

                return Convert.ToBase64String(bytes);
            }
        }
    }
}
