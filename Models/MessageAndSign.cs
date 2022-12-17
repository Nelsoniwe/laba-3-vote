using System.Security.Cryptography;

namespace laba3_vote.Models
{
    public class MessageAndSign
    {
        public string Message { get; set; }
        public byte[] Sign { get; set; }

        public DSAParameters SignKey { get; set; }

        public MessageAndSign(string message, byte[] sign, DSAParameters signKey)
        {
            Message = message;
            Sign = sign;
            this.SignKey = signKey;
        }
    }
}