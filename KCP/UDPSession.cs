using System;
using System.Net;
using System.Net.Sockets;
using Force.Crc32;

namespace KcpProject
{
    class UDPSession
    {
        private Socket mSocket = null;
        private KCP mKCP = null;
        private BlockCrypt block;
        private int headerSize;

        private ByteBuffer mRecvBuffer = ByteBuffer.Allocate(1024 * 32);

        private UInt32 mNextUpdateTime = 0;

        // 16-bytes nonce for each packet
        private const int nonceSize = 16;

        // 4-bytes packet checksum
        private const int crcSize = 4;

        // overall crypto header size
        private const int cryptHeaderSize = nonceSize + crcSize;


        public bool IsConnected
        {
            get { return mSocket != null && mSocket.Connected && mKCP != null && mKCP.State != 0xFFFFFFFF; }
        }
        
       

        public bool WriteDelay { get; set; }

        public void Connect(string host, int port, BlockCrypt b)
        {
            
            var endpoint = IPAddress.Parse(host);
            mSocket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            mSocket.Connect(endpoint, port);
            mKCP = new KCP((uint) (new Random().Next(1, Int32.MaxValue)), rawSend);
            // normal:  0, 40, 2, 1
            // fast:    0, 30, 2, 1
            // fast2:   1, 20, 2, 1
            // fast3:   1, 10, 2, 1
            mKCP.NoDelay(0, 30, 2, 1);
            mRecvBuffer.Clear(); 
            headerSize = 0;
            block = b;
            if (block != null)
            {
                headerSize += cryptHeaderSize;
            }

            mKCP.ReserveBytes(headerSize);
        }

        public void Close()
        {
            if (mSocket != null)
            {
                mSocket.Close();
                mSocket = null;
                mRecvBuffer.Clear();
            }
            mKCP.Clear();
            mKCP = null;
        }

        private void rawSend(byte[] data, int length)
        {
            if (mSocket != null)
            {
                if (block != null)
                {
                    if (length <= cryptHeaderSize)
                    {
                        return;
                    }

                    //fill header space 16bytes
                    //checksum
                    var checksum = Crc32Algorithm.Compute(data, cryptHeaderSize, length - cryptHeaderSize);
                    KCP.ikcp_encode32u(data, nonceSize, checksum);
//                    Console.WriteLine(checksum);
//                    PrintByteArray(data, length);
                    //enrypt
                    block.Encrypt(data, 0, length);
//                    PrintByteArray(data, length);
                }
                var ret = mSocket.Send(data, length, SocketFlags.None);
//                Console.WriteLine(mKCP.SegCount);
            }
        }

//        static void PrintByteArray(byte[] bytes, int len)
//        {
//            var sb = new StringBuilder("byte[] = ");
//            int i = 0;
//
//            foreach (var b in bytes)
//                if (i++ < len)
//                    sb.Append(b + ", ");
//            Console.WriteLine(sb.ToString());
//        }

        public int Send(byte[] data, int index, int length)
        {
            if (mSocket == null)
                return -1;

            if (mKCP.WaitSnd >= mKCP.SndWnd)
            {
                return 0;
            }

            mNextUpdateTime = 0;

            var n = mKCP.Send(data, index, length);

            if (mKCP.WaitSnd >= mKCP.SndWnd || !WriteDelay)
            {
                mKCP.Flush(false);
            }

            return n;
        }

        public int Recv(byte[] data, int index, int length)
        {
            // 上次剩下的部分
            if (mRecvBuffer.ReadableBytes > 0)
            {
                var recvBytes = Math.Min(mRecvBuffer.ReadableBytes, length);
                Buffer.BlockCopy(mRecvBuffer.RawBuffer, mRecvBuffer.ReaderIndex, data, index, recvBytes);
                mRecvBuffer.ReaderIndex += recvBytes;
                // 读完重置读写指针
                if (mRecvBuffer.ReaderIndex == mRecvBuffer.WriterIndex)
                {
                    mRecvBuffer.Clear();
                }

                return recvBytes;
            }

            if (mSocket == null)
                return -1;

            if (!mSocket.Poll(0, SelectMode.SelectRead))
            {
                return 0;
            }

            var rn = 0;
            try
            {
                rn = mSocket.Receive(mRecvBuffer.RawBuffer, mRecvBuffer.WriterIndex, mRecvBuffer.WritableBytes,
                    SocketFlags.None);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                rn = -1;
            }

            if (rn <= 0)
            {
                return rn;
            }

            mRecvBuffer.WriterIndex += rn;

            // 检查加密
            if (block != null)
            {
                block.Decrypt(mRecvBuffer.RawBuffer, mRecvBuffer.ReaderIndex, mRecvBuffer.ReadableBytes);
                var checksum = Crc32Algorithm.Compute(mRecvBuffer.RawBuffer, mRecvBuffer.ReaderIndex + cryptHeaderSize,
                    mRecvBuffer.ReadableBytes - cryptHeaderSize);
                uint data_checksum = 0;
                KCP.ikcp_decode32u(mRecvBuffer.RawBuffer, mRecvBuffer.ReaderIndex + nonceSize, ref data_checksum);
//                Console.WriteLine("checksum "+checksum+" ="+data_checksum);
                if (checksum == data_checksum)
                {
                    mRecvBuffer.ReaderIndex += cryptHeaderSize;
                }
                else
                {
                    // 丢弃数据包
                    rn = -1;
                    return rn;
                }
            }

            var inputN = mKCP.Input(mRecvBuffer.RawBuffer, mRecvBuffer.ReaderIndex, mRecvBuffer.ReadableBytes, true,
                true);
            if (inputN < 0)
            {
                mRecvBuffer.Clear();
                return inputN;
            }

            mRecvBuffer.Clear();

            // 读完所有完整的消息
            for (;;)
            {
                var size = mKCP.PeekSize();
                if (size <= 0) break;

                mRecvBuffer.EnsureWritableBytes(size);

                var n = mKCP.Recv(mRecvBuffer.RawBuffer, mRecvBuffer.WriterIndex, size);
                if (n > 0) mRecvBuffer.WriterIndex += n;
            }

            // 有数据待接收
            if (mRecvBuffer.ReadableBytes > 0)
            {
                return Recv(data, index, length);
            }

            return 0;
        }

        public void Update()
        {
            if (mSocket == null)
                return;

            if (0 == mNextUpdateTime || mKCP.CurrentMS >= mNextUpdateTime)
            {
                mKCP.Update();
                mNextUpdateTime = mKCP.Check();
            }
        }

       
    }
}