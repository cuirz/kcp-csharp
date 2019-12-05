using System;
using System.IO;
using System.Security.Cryptography;

namespace KcpProject
{
    public interface BlockCrypt
    {
        
        byte[] Encrypt(byte[] src);
        // Encrypt encrypts the whole block in src into dst.
        // Dst and src may point at the same memory.
        void Encrypt(byte[] src, int offset, int length);

        
        byte[] Decrypt(byte[] src);
        // Decrypt decrypts the whole block in src into dst.
        // Dst and src may point at the same memory.
        void Decrypt(byte[] src, int offset, int length);
    }


    public class AesBlockCrypt : BlockCrypt
    {
        private static byte[] Zeros = new byte[16];

        private static byte[] InitialVector = new byte[]
            {167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107};

        private ICryptoTransform Encryptor;
        private ICryptoTransform Decryptor;

        public AesBlockCrypt(byte[] key)
        {
            var rijndael = new RijndaelManaged();
            rijndael.Key = key;
            rijndael.Mode = CipherMode.CFB;
            rijndael.Padding = PaddingMode.Zeros;
            rijndael.FeedbackSize = 128;
            rijndael.IV = InitialVector;
            Encryptor = rijndael.CreateEncryptor();
            Decryptor = rijndael.CreateDecryptor();
        }

        public byte[] Encrypt(byte[] src)
        {
            using (var stream = new MemoryStream())
            using (var cs = new CryptoStream(stream, Encryptor, CryptoStreamMode.Write))
            {
                cs.Write(src, 0, src.Length);
                cs.Write(Zeros, 0, FillIn(src.Length));
                stream.SetLength(src.Length);
                return stream.ToArray();
            }
        }


        public void Encrypt(byte[] src, int offset, int length)
        {
            using (var stream = new MemoryStream())
            using (var cs = new CryptoStream(stream, Encryptor, CryptoStreamMode.Write))
            {
                cs.Write(src, offset, length);
                cs.Write(Zeros, 0, FillIn(length));
                Buffer.BlockCopy(stream.ToArray(), 0, src, offset, length);
            }
        }

        public byte[] Decrypt(byte[] src)
        {
            using (var stream = new MemoryStream())
            using (var cs = new CryptoStream(stream, Decryptor, CryptoStreamMode.Write))
            {
                cs.Write(src, 0, src.Length);
                cs.Write(Zeros, 0, FillIn(src.Length));
                stream.SetLength(src.Length);
                return stream.ToArray();
            }
        }

        public void Decrypt(byte[] src, int offset, int length)
        {
            using (var stream = new MemoryStream())
            using (var cs = new CryptoStream(stream, Decryptor, CryptoStreamMode.Write))
            {
                cs.Write(src, offset, length);
                cs.Write(Zeros, 0, FillIn(length));
                Buffer.BlockCopy(stream.ToArray(), 0, src, offset, length);
            }
        }

        private int FillIn(int len)
        {
            var r = len % 16;
            return (r == 0 ? 0 : 16 - r);
        }
    }
}