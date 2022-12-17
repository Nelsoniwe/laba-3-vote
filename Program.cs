using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using laba3_vote.Models;
using System.Runtime.ConstrainedExecution;

namespace laba3_vote
{
    internal class Program
    {
        static void Main(string[] args)
        {
            CVK cvk = new CVK(@"Persons.json", @"Votes.json", @"RegisteredPersons.json");
            BR br = new BR();
            cvk.Load();

            Person currentUser = null;
            MessageAndSign returnedMessage = null;

            while (true)
            {
                Console.Clear();
                Console.WriteLine("1. Choose Person\n2. Create Person\n3. Delete Person\n4. Watch Results\n5. exit");
                string action = Console.ReadLine();
                

                if (action == "1")
                {
                    Console.Clear();

                    if (cvk.People.FindAll(x => x.Role == Role.voter).Count > 0)
                    {

                        var people = cvk.People.FindAll(x => x.Role == Role.voter);
                        foreach (var item in people)
                        {
                            Console.WriteLine($"{item.Id} Role: {item.Role} Name: {item.Name} Surname: {item.Surname}");
                        }

                        Console.WriteLine("Choose person");
                        var id = Console.ReadLine();
                        var result = cvk.People.FirstOrDefault(x => x.Id == id);
                        if (result != null && result.Role == Role.voter)
                        {
                            currentUser = result;
                            break;
                        }
                        else
                        {
                            Console.WriteLine("Person don't exist");
                            Console.ReadLine();
                        }

                    }
                    else
                    {
                        Console.WriteLine("People don't exist");
                        Console.ReadLine();
                    }
                }
                if (action == "2")
                {
                    Console.Clear();
                    Console.WriteLine("Write a name:");
                    var name = Console.ReadLine();
                    Console.WriteLine("Write a surname:");
                    var surname = Console.ReadLine();

                    Console.WriteLine($"Write a role: ({Role.applicant}, {Role.voter})");
                    var role = Console.ReadLine();

                    if (name != "" && surname != "" && Enum.IsDefined(typeof(Role), role))
                    {
                        var random = new Random();
                        string id = random.Next(100000000).ToString();

                        while (cvk.People.FirstOrDefault(x => x.Id == id) != null)
                        {
                            id = random.Next(1000000).ToString();
                        }

                        cvk.People.Add(new Person(id, name, surname, (Role)Enum.Parse(typeof(Role), role)));
                        cvk.Save();
                        continue;
                    }
                }
                if (action == "3")
                {
                    Console.Clear();
                    var people = cvk.People;

                    if (people.Count == 0)
                    {
                        Console.WriteLine("People don't exist");
                        Console.ReadLine();
                        continue;
                    }

                    foreach (var item in people)
                    {
                        Console.WriteLine($"{item.Id} Role: {item.Role} Name: {item.Name} Surname: {item.Surname}");
                    }

                    Console.WriteLine("Choose person");

                    var id = Console.ReadLine();
                    var result = cvk.People.FirstOrDefault(x => x.Id == id);
                    if (result != null)
                    {
                        cvk.People.Remove(result);
                        continue;
                    }
                    else
                    {
                        Console.WriteLine("Person doesn't exist");
                        Console.ReadLine();
                    }
                }
                if (action == "4")
                {
                    var people = cvk.People.FindAll(x => x.Role == Role.applicant);

                    foreach (var item in people)
                    {
                        Console.WriteLine($"Id: {item.Id} Name: {item.Name} Surname: {item.Surname} Votes: {cvk.GetVotesById(item.Id)}");
                    }
                    Console.ReadLine();
                    continue;
                }
                if (action == "5")
                {
                    break;
                }
            }

            while (true)
            {


                Console.Clear();
                if (currentUser == null)
                {
                    Console.WriteLine("Current user doesn't exist");
                    break;
                }

                if (currentUser.Voted == true && currentUser.Permission != true)
                {
                    Console.WriteLine("Current user can't vote");
                    break;
                }

                Tuple<string, string> encryptionKeys = cvk.GenerateElgamalKeys();
                string encryptionPublicKey = encryptionKeys.Item1;
                string encryptionPrivateKey = encryptionKeys.Item2;

                returnedMessage = br.RegisterUid(currentUser.Id, encryptionPublicKey,cvk);

                if (returnedMessage == null)
                {
                    Console.WriteLine("You already voted or not registered");
                    break;
                }

                if (!cvk.VerifySignedHash(
                        Encoding.UTF8.GetBytes(returnedMessage.Message),
                        returnedMessage.Sign,
                        returnedMessage.SignKey
                    ))
                {
                    Console.WriteLine("signature did not match");
                    return;
                }

                string uid = cvk.Decrypt(cvk.GenerateElgamalKeys().Item2, returnedMessage.Message);

                Console.WriteLine("Write id of the applicant you want to vote for");

                var people = cvk.People.FindAll(x => x.Role == Role.applicant);

                foreach (var item in people)
                {
                    Console.WriteLine($"Id: {item.Id} Name: {item.Name} Surname: {item.Surname}");
                }

                var id = Console.ReadLine();
                var choosenApplicant = cvk.People.FirstOrDefault(x => x.Id == id);

                if (choosenApplicant == null)
                {
                    Console.WriteLine("Applicant doesn't exist");
                    Console.ReadLine();
                    break;
                }

                string generatedId = cvk.GetHashString(uid);
                Console.WriteLine($"Your ID: {generatedId}");


                DSACryptoServiceProvider DSA = new DSACryptoServiceProvider(1024);

                DSAParameters DSAPrivateKey = DSA.ExportParameters(true);
                DSAParameters DSAPublicKey = DSA.ExportParameters(false);

                cvk.People.FirstOrDefault(x => x.Id == currentUser.Id).Uid = uid;
                cvk.Save();

                string message = uid + '|' + generatedId + '|' + choosenApplicant.Id;
                string encryptedMessage = cvk.Encrypt(encryptionPublicKey, message);

                MessageAndSign bulletin = new MessageAndSign(
                    encryptedMessage,
                    cvk.HashAndSignBytes(Encoding.UTF8.GetBytes(encryptedMessage), DSAPrivateKey),
                    DSAPublicKey
                );

                bool result = cvk.Vote(bulletin);

                Console.WriteLine("Success");
                Console.ReadLine();
                break;
            }

            cvk.Save();

        }
    }
}
