using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using DTLS;
using System.Diagnostics;

namespace CoAP.Channel
{
    /// <summary>
    /// Channel via UDP protocol.
    /// </summary>
    public partial class DTLSClientChannel : IChannel
    {
        DTLS.Client dtlsClient;

        private Int32 _running;

        public event EventHandler<DataReceivedEventArgs> DataReceived;
        public event EventHandler<DTLS.PSKEventArgs> FindKey;

        public DTLSClientChannel(string Identity, byte[] Key, TCipherSuite Cipher)
        {
            dtlsClient = new Client(new IPEndPoint(IPAddress.Any, 0));
            dtlsClient.DataReceived += dtlsClient_DataReceived;
            dtlsClient.SetVersion(new Version(1, 2));
            dtlsClient.PSKIdentities.AddIdentity(Identity, Key);
            dtlsClient.SupportedCipherSuites.Add(Cipher);
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint
        {
            get
            {
                return dtlsClient.LocalEndPoint;
            }
        }

        /// <inheritdoc/>
        public void Start()
        {
        }

        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0)
                return;

            if (dtlsClient != null) dtlsClient.Stop();
        }

        public void Send(Byte[] data, System.Net.EndPoint ep)
        {
            Trace.WriteLine("DTLS client channel Need to send bytes");

            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) == 0)
            {
                Console.WriteLine("Connecting to server...");
                dtlsClient.ConnectToServer(ep);
            }
            Console.WriteLine("Sending byte snow");
            dtlsClient.Send(data);
        }

        public void Dispose()
        {
            Stop();
        }

        void dtlsClient_DataReceived(System.Net.EndPoint endPoint, byte[] data)
        {
            Trace.WriteLine(string.Format("DTLS Client Read: {0}", BitConverter.ToString(data)));

            if (DataReceived!=null)
            {
                DataReceivedEventArgs args = new DataReceivedEventArgs(data, endPoint);
                DataReceived(this, args);
            }

        }

        static byte[] HexToBytes(string hex)
        {
            byte[] result = new byte[hex.Length / 2];
            int count = 0;
            for (int index = 0; index < hex.Length; index += 2)
            {
                result[count] = Convert.ToByte(hex.Substring(index, 2), 16);
                count++;
            }
            return result;
        }
    }
}