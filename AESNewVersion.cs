﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

//--------------------------------------------
// New encrypt/decrypt method in version 1.4
//--------------------------------------------
namespace QuasarDecryptor
{
    public static class AESNewVersion
    {
        private const int KeyLength = 32;
        private const int AuthKeyLength = 64;
        private const int IvLength = 16;
        private const int HmacSha256Length = 32;
        private static byte[] _key;
        private static byte[] _authKey;

        private static readonly byte[] Salt =
        {
            0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B, 0xB2, 0x19, 0x2, 0x24, 0x30, 0xA5, 0x78, 0x43, 0x0, 0x3D, 0x56,
            0x44, 0xD2, 0x1E, 0x62, 0xB9, 0xD4, 0xF1, 0x80, 0xE7, 0xE6, 0xC3, 0x39, 0x41
        };

        public static void SetDefaultKey(string masterKey)
        {
            if (string.IsNullOrEmpty(masterKey))
                throw new ArgumentException($"{nameof(masterKey)} can not be null or empty.");

            using (Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(masterKey, Salt, 50000))
            {
                _key = derive.GetBytes(KeyLength);
                _authKey = derive.GetBytes(AuthKeyLength);
            }
        }

        public static string Decrypt(string input)
        {
            return Encoding.UTF8.GetString(Decrypt2(Convert.FromBase64String(input)));
        }

        public static byte[] Decrypt2(byte[] input)
        {
            if (input == null)
                throw new ArgumentNullException($"{nameof(input)} can not be null.");

            using (var ms = new MemoryStream(input))
            {
                using (var aesProvider = new AesCryptoServiceProvider())
                {
                    aesProvider.KeySize = 256;
                    aesProvider.BlockSize = 128;
                    aesProvider.Mode = CipherMode.CBC;
                    aesProvider.Padding = PaddingMode.PKCS7;
                    aesProvider.Key = _key;

                    // read first 32 bytes for HMAC
                    using (var hmac = new HMACSHA256(_authKey))
                    {
                        var hash = hmac.ComputeHash(ms.ToArray(), HmacSha256Length, ms.ToArray().Length - HmacSha256Length);
                        byte[] receivedHash = new byte[HmacSha256Length];
                        ms.Read(receivedHash, 0, receivedHash.Length);

                    }

                    byte[] iv = new byte[IvLength];
                    ms.Read(iv, 0, IvLength); // read next 16 bytes for IV, followed by ciphertext
                    aesProvider.IV = iv;

                    using (var cs = new CryptoStream(ms, aesProvider.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        byte[] temp = new byte[ms.Length - IvLength + 1];
                        byte[] data = new byte[cs.Read(temp, 0, temp.Length)];
                        Buffer.BlockCopy(temp, 0, data, 0, data.Length);
                        return data;
                    }
                }
            }
        }
    }
}
