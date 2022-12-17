using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace laba3_vote.Models
{
    public static class Xor
    {
        //генератор повторений пароля
        private static string GetRepeatKey(string s, int n)
        {
            var r = s;
            while (r.Length < n)
            {
                r += r;
            }

            return r.Substring(0, n);
        }

        //метод шифрования/дешифровки
        private static string Cipher(string text, string secretKey)
        {
            var currentKey = GetRepeatKey(secretKey, text.Length);
            var res = string.Empty;
            for (var i = 0; i < text.Length; i++)
            {
                res += ((char)(text[i] ^ currentKey[i])).ToString();
            }

            return res;
        }

        //шифрование текста
        public static string Encrypt(string text, string secretKey)
            => Cipher(text, secretKey);

        //расшифровка текста
        public static string Decrypt(string text, string secretKey)
            => Cipher(text, secretKey);
    }
}
