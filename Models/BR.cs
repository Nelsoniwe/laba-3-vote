using laba3_vote.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace laba3_vote.Models
{
    public class BR
    {
        //CVK cvk = new CVK(@"Persons.json", @"Votes.json", @"RegisteredPersons.json");

        public MessageAndSign RegisterUid(string voterId, string encryptionPublicKey,CVK cvk)
        {
            Person voter = cvk.People.FirstOrDefault(x => x.Id == voterId);

            StringBuilder sb = new StringBuilder();
            HashAlgorithm algorithm = SHA256.Create();

            foreach (byte b in algorithm.ComputeHash(Encoding.UTF8.GetBytes(voter.Name + ' ' + voter.Surname)))
                sb.Append(b.ToString("X2"));

            string uid = sb.ToString();

            RegisteredPerson registeredPerson = cvk.RegisteredPersons.Where(r => r.Person?.Id == voterId).FirstOrDefault();

            if (voter.Permission == false)
            {
                return null;
            }

            if (voter.Voted)
            {
                return null;
            }

            if (registeredPerson== null)
            {
                registeredPerson = new RegisteredPerson() { uid = uid, Person = voter };
                cvk.RegisteredPersons.Add(registeredPerson);
            }

            string encryptedUid = cvk.Encrypt(encryptionPublicKey, uid);

            DSACryptoServiceProvider DSA = new DSACryptoServiceProvider(1024);

            DSAParameters DSAPrivateKey = DSA.ExportParameters(true);
            DSAParameters DSAPublicKey = DSA.ExportParameters(false);

            byte[] sign = cvk.HashAndSignBytes(Encoding.UTF8.GetBytes(encryptedUid), DSAPrivateKey);

            MessageAndSign encryptedMessageAndSign = new MessageAndSign(encryptedUid, sign, DSAPublicKey);

            cvk.Save();
            
            return encryptedMessageAndSign;
        }

    }
}
