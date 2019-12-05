using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Force.Crc32;

namespace KcpProject.Sample
{
    class Program
    {
        static void PrintByteArray(byte[] bytes,int len)
        {
            var sb = new StringBuilder("byte[] = ");
            int i = 0;
 
            foreach (var b in bytes)
                if(i++ < len)
                    sb.Append(b + ", ");
            Console.WriteLine(sb.ToString());
        }
        static void Main(string[] args)
        {
            var salt = "demo salt";
            var password = "demo pass";
            var interactions = 1024;


            var df = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt),interactions);
            var key = df.GetBytes(32);
            var aes = new AesBlockCrypt(key);
            var checksum = Crc32Algorithm.Compute(new byte[]{0,0,0,0,1,2,3,4,5,6},4,10-4);
            Console.WriteLine(checksum);
            var connection = new UDPSession();
            connection.Connect("192.168.1.29", 10000,aes);
            Console.WriteLine("begin udpsession kcp");

            var firstSend = true;
            var buffer = new byte[1024];
            var counter = 0;

            DateTime resetTime = DateTime.Now;
            while (true)
            {
                if (!connection.IsConnected)
                {
                    Console.WriteLine("断开连接");
                    Thread.Sleep(1000);
                    connection.Close();
                    connection.Connect("192.168.1.29", 10000,aes);
                    continue;
                }
                connection.Update();


                var cur = DateTime.Now.Subtract(resetTime);
                if (firstSend && cur.TotalMilliseconds > 0)
                {
                    resetTime = DateTime.Now;
                    //firstSend = false;
                    // Console.WriteLine("Write Message...");
                    var text = Encoding.UTF8.GetBytes(string.Format("Hello KCP: {0}", ++counter));
                    if (connection.Send(text, 0, text.Length) < 0)
                    {
                        Console.WriteLine("Write message failed.");
                        break;
                    }

                    Thread.Sleep(10);
                }

                var n = connection.Recv(buffer, 0, buffer.Length);
                if (n == 0)
                {
                    Thread.Sleep(10);
                    continue;
                }
                else if (n < 0)
                {
                    Console.WriteLine("Receive Message failed.");
                    break;
                }

                var resp = Encoding.UTF8.GetString(buffer, 0, n);
                Console.WriteLine("Received Message: " + resp);
            }
        }
    }
    
    
}