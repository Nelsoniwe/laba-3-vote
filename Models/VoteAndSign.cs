namespace laba3_vote.Models
{
    public class VoteAndSign
    {
        public byte[] Message { get; set; }
        public byte[] Sign { get; set; }
        public VoteAndSign(byte[] message, byte[] sign)
        {
            Message = message;
            Sign = sign;
        }
    }
}