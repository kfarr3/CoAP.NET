using System;
using CoAP.Examples.Resources;
using CoAP.Server;
using CoAP.Net;
using DTLS;

namespace CoAP.Examples
{
    public class ExampleServer
    {
        public static void Main(String[] args)
        {
            CoapServer server = new CoapServer();

            server.Add(new HelloWorldResource("hello"));
            server.Add(new FibonacciResource("fibonacci"));
            server.Add(new StorageResource("storage"));
            server.Add(new ImageResource("image"));
            server.Add(new MirrorResource("mirror"));
            server.Add(new LargeResource("large"));
            server.Add(new CarelessResource("careless"));
            server.Add(new SeparateResource("separate"));
            server.Add(new TimeResource("time"));

            // Create a Secure endpoint
            CoAPEndPoint ep = new CoAPEndPoint(true);
            ep.FindKey += dtlsServer_FindKey; // Because it's secured, add the FindKey callback
            server.AddEndPoint(ep);            

            ep = new CoAPEndPoint(5683);
            server.AddEndPoint(ep);

            try
            {
                server.Start();

                Console.Write("CoAP server [{0}] is listening on", server.Config.Version);

                foreach (var item in server.EndPoints)
                {
                    Console.Write(" ");
                    Console.Write(item.LocalEndPoint);
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        static void dtlsServer_FindKey(object sender, PSKEventArgs e)
        {
            Console.WriteLine("Searching for key for {0}", BitConverter.ToString(e.Identity));
            e.Key = new byte[] { 0x7C, 0xCD, 0xE1, 0x4A, 0x5C, 0xF3, 0xB7, 0x1C, 0x0C, 0x08, 0xC8, 0xB7, 0xF9, 0xE5 };
        }
    }
}
