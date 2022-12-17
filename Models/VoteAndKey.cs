using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace laba3_vote.Models
{
    public class VoteAndKey
    {
        public byte[]? Message { get; set; }
        public RSACryptoServiceProvider? Key { get; set; }
        public VoteAndKey(byte[] encMessage, RSACryptoServiceProvider rSAPrivateKey)
        {
            Message = encMessage;
            Key = rSAPrivateKey;
        }

        public VoteAndKey(){}
    }
}
