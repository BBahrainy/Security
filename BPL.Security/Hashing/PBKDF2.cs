using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BPL.Security.Hashing
{

    public static class PBKDF2
    {
        public const int SALT_SIZE = 32; // size in bytes
        public const int HASH_SIZE = 24; // size in bytes
        public const int ITERATIONS = 100000; // number of pbkdf2 iterations
        public const int PasswordHashLengh = 32;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input">password raw string</param>
        /// <param name="preferedSalt">prefered salt which should be 32 byte converted as Base64 string</param>
        /// <returns>will contain hashed input and the salt</returns>
        public static PBKDF2Result ComputeHash(string input, string preferedSalt = "")
        {
            byte[] salt = null;
            if (!string.IsNullOrWhiteSpace(preferedSalt))
            {
                salt = Convert.FromBase64String(preferedSalt);
            }
            else
            {
                // Generate a salt
                using (RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider())
                {
                    salt = new byte[SALT_SIZE];
                    provider.GetBytes(salt);
                }
            }

            // Generate the hash
            PBKDF2Result result = new PBKDF2Result();
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(input, salt, ITERATIONS))
            {
                byte[] hashedValue = pbkdf2.GetBytes(HASH_SIZE);
                result.Value = Convert.ToBase64String(hashedValue);
                result.Salt = Convert.ToBase64String(salt);
            }

            return result;
        }
    }
}
