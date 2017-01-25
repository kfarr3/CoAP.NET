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
    public partial class DTLSServerChannel : IChannel
    {
        public DTLS.Server dtlsServer;

        private Int32 _running;

        public event EventHandler<DataReceivedEventArgs> DataReceived;
        public event EventHandler<DTLS.PSKEventArgs> FindKey;

        public DTLSServerChannel()
        {
            dtlsServer = new DTLS.Server(new IPEndPoint(IPAddress.Any, 5684));
            dtlsServer.DataReceived += new DTLS.Server.DataReceivedEventHandler(dtlsServer_DataReceived);
            dtlsServer.PSKIdentities.PSKKeySearch += dtlsServer_FindKey;
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint
        {
            get
            {
                return dtlsServer.LocalEndPoint;
            }
        }

        /// <inheritdoc/>
        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0)
                return;

            if (dtlsServer!=null) dtlsServer.Start();
        }

        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0)
                return;

            if (dtlsServer!=null) dtlsServer.Stop();
        }

        public void Send(Byte[] data, System.Net.EndPoint ep)
        {
            Trace.WriteLine(String.Format("DTLS sending {0} bytes", data.Length));
            dtlsServer.Send(ep, data);
        }

        public void Dispose()
        {
            Stop();
        }

        void dtlsServer_DataReceived(System.Net.EndPoint endPoint, byte[] data)
        {
            Trace.WriteLine(String.Format("DTLS Server Read: {0}", BitConverter.ToString(data)));

            if (DataReceived!=null)
            {
                DataReceivedEventArgs args = new DataReceivedEventArgs(data, endPoint);
                DataReceived(this, args);
            }

        }

        void dtlsServer_FindKey(object sender, PSKEventArgs e)
        {
            Console.WriteLine("Searching for key for {0}", BitConverter.ToString(e.Identity));

            if (FindKey!=null)
            {
                FindKey(sender, e);
            }

            //e.Key = HexToBytes("7CCDE14A5CF3B71C0C08C8B7F9E5");
        }

        /*static byte[] HexToBytes(string hex)
        {
            byte[] result = new byte[hex.Length / 2];
            int count = 0;
            for (int index = 0; index < hex.Length; index += 2)
            {
                result[count] = Convert.ToByte(hex.Substring(index, 2), 16);
                count++;
            }
            return result;
        }*/
    }
}