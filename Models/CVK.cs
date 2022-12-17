using laba3_vote.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace laba3_vote.Models
{
    public class CVK
    {
        UnicodeEncoding byteConverter = new UnicodeEncoding();

        private Tuple<string, string> keys;

        public List<Person> People { get; set; } = new List<Person>();

        private List<Vote> Votes { get; set; } = new List<Vote>();

        public List<RegisteredPerson> RegisteredPersons { get; set; } = new List<RegisteredPerson>();

        private string personsPath;
        private string votesPath;
        private string registeredPersonsPath;

        public CVK(string PersonsPath, string VotesPath, string registeredPersonsPath)
        {
            personsPath = PersonsPath;
            votesPath = VotesPath;
            this.registeredPersonsPath = registeredPersonsPath;
            keys = GenerateElgamalKeys();
        }

        public void Load()
        {
            FileInfo fi = new FileInfo(personsPath);
            FileStream fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);

            using (StreamReader r = new StreamReader(fs))
            {
                string json = r.ReadToEnd();
                if (json != "")
                {
                    People = JsonSerializer.Deserialize<List<Person>>(json);
                }
            }

            fi = new FileInfo(votesPath);
            fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);

            using (StreamReader r = new StreamReader(fs))
            {
                string json = r.ReadToEnd();
                if (json != "")
                {
                    Votes = JsonSerializer.Deserialize<List<Vote>>(json);
                }
            }

            fi = new FileInfo(registeredPersonsPath);
            fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);

            using (StreamReader r = new StreamReader(fs))
            {
                string json = r.ReadToEnd();
                if (json != "")
                {
                    RegisteredPersons = JsonSerializer.Deserialize<List<RegisteredPerson>>(json);
                }
            }
        }


        public void Save()
        {
            string jsonPeople = JsonSerializer.Serialize(People);
            File.WriteAllText(personsPath, jsonPeople);

            string jsonVotes = JsonSerializer.Serialize(Votes);
            File.WriteAllText(votesPath, jsonVotes);

            string jsonRegisteredPersons = JsonSerializer.Serialize(RegisteredPersons);
            File.WriteAllText(registeredPersonsPath, jsonRegisteredPersons);
        }

       

        public bool Vote(MessageAndSign messageAndSign)
        {
            if (!VerifySignedHash(Encoding.UTF8.GetBytes(messageAndSign.Message), messageAndSign.Sign, messageAndSign.SignKey))
            {
                return false;
            }

            string[] bulletin = Decrypt(keys.Item1, messageAndSign.Message).Split('|');
            string voterUid = bulletin[0];
            string voterId = bulletin[1];
            string candidateId = bulletin[2];

            RegisteredPersons.Remove(RegisteredPersons.FirstOrDefault(x => x.uid == voterUid));
            People.FirstOrDefault(x => x.Uid == voterUid).Voted = true;
            Votes.Add(new Vote(voterId, candidateId));

            return true;
        }

        public int GetVotesById(string id)
        {
            var applicant = People.FirstOrDefault(x => x.Id == id && x.Role == Role.applicant);
            if (applicant != null)
                return Votes.Where(x => x.ForWho == id).Count();
            return 0;
        }


        public Tuple<string, string> GenerateElgamalKeys()
        {
            var random = new Random();
            var p = 850;

            var prime = 28;
            var generator = 180;

            var aliceK = random.Next(1, 100);
            var alicePublicKey = BigInteger.ModPow(generator, aliceK, prime);

            var output = prime + " " + generator + " ";
            var privateKeyText = output + aliceK + " ";
            var publicKeyText = output + alicePublicKey + " ";

            return Tuple.Create(privateKeyText, publicKeyText);

        }

        public string Encrypt(string publicKey, string message)
        {
            var publicKeyLines = publicKey.Split(' ');
            var messageLines = message.Split('|');

            var messege = BigInteger.Parse(publicKeyLines[0]);
            var prime = BigInteger.Parse(publicKeyLines[1]);

            var generator = BigInteger.Parse(publicKeyLines[1]);
            var alicePublicKey = BigInteger.Parse(publicKeyLines[2]);

            var random = new Random();
            var bobK = random.Next(1, 100);

            var bobPublicKey = BigInteger.ModPow(generator, bobK, prime);

            var encryptionKey = BigInteger.ModPow(alicePublicKey, bobK, prime);

            var encryptedMessage = (messege * encryptionKey) % prime;
            var output = bobPublicKey + " " + encryptedMessage + " ";
            return message;
        }

        public string Decrypt(string privateKey, string encryptedMessage)
        {
            var privateKeyLines = privateKey.Split(' ');
            var encryptedMessageLines = privateKeyLines;


            var prime = BigInteger.Parse(privateKeyLines[0]);
            var generator = BigInteger.Parse(privateKeyLines[1]);

            var bobPublicKey = BigInteger.Parse(encryptedMessageLines[0]);
            var bobK = 1;
            while (true)
            {
                if (BigInteger.ModPow(generator, bobK, prime) == bobPublicKey)
                    break;

                bobK++;
                break;
            }

            var aliceK = BigInteger.Parse(privateKeyLines[2]);
            var alicePublicKey = BigInteger.ModPow(generator, aliceK, prime);

            var encryptionKey = BigInteger.ModPow(alicePublicKey, bobK, prime);

            var encryptedMesege = BigInteger.Parse(encryptedMessageLines[1]);
            var decryptedMessege = encryptedMessage;
            var encryptionKeyInverse = BigInteger.ModPow(encryptionKey, prime - 2, prime);
            var decryptedMessage = (encryptedMesege * encryptionKeyInverse) % prime;

            var output = decryptedMessege;
            return output;
        }

        public bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, DSAParameters Key)
        {
            try
            {
                DSACryptoServiceProvider DSAalg = new DSACryptoServiceProvider();

                DSAalg.ImportParameters(Key);

                return DSAalg.VerifyData(DataToVerify, SignedData);
            }
            catch (CryptographicException e)
            {
                return false;
            }
        }

        public byte[] HashAndSignBytes(byte[] DataToSign, DSAParameters Key)
        {
            try
            {
                DSACryptoServiceProvider DSAalg = new DSACryptoServiceProvider();

                DSAalg.ImportParameters(Key);

                return DSAalg.SignData(DataToSign, HashAlgorithmName.SHA1);
            }
            catch (CryptographicException e)
            {
                return null;
            }
        }

        public byte[] GetHash(string inputString)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
                return algorithm.ComputeHash(Encoding.UTF8.GetBytes(inputString));
        }

        public string GetHashString(string inputString)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in GetHash(inputString))
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }
    }
}
