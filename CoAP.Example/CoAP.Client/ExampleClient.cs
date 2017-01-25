using System;
using System.Collections.Generic;
using CoAP.Util;
using DTLS;

#if DNX451
using Common.Logging;
using Common.Logging.Configuration;

namespace CoAP.Client.DNX
{
	// DNX entry point
	public class Program
	{
		public void Main(string[] args)
		{
			NameValueCollection console_props = new NameValueCollection();
			console_props["showDateTime"] = "true";
			console_props["level"] = "Debug";
			LogManager.Adapter = new Common.Logging.Simple.ConsoleOutLoggerFactoryAdapter(console_props);
			CoAP.Examples.ExampleClient.Main(args);
		}
	}
}
#endif

namespace CoAP.Examples
{

	// .NET 2, .NET 4 entry point
	class ExampleClient
    {
        static string SecureIdentity = "192.168.21.220";
        static byte[] SecureKey = new byte[] { 0x7C, 0xCD, 0xE1, 0x4A, 0x5C, 0xF3, 0xB7, 0x1C, 0x0C, 0x08, 0xC8, 0xB7, 0xF9, 0xE5 };
        static TCipherSuite SecureCipher = TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8;

        public static void Main(String[] args)
        {
            String method = null;
            Uri uri = null;
            String payload = null;
            Boolean loop = false;
            Boolean byEvent = true;

            if (args.Length == 0)
                PrintUsage();

            Int32 index = 0;
            foreach (String arg in args)
            {
                if (arg[0] == '-')
                {
                    if (arg.Equals("-l"))
                        loop = true;
                    if (arg.Equals("-e"))
                        byEvent = true;
                    else
                        Console.WriteLine("Unknown option: " + arg);
                }
                else
                {
                    switch (index)
                    {
                        case 0:
                            method = arg.ToUpper();
                            break;
                        case 1:
                            try
                            {
                                uri = new Uri(arg);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("Failed parsing URI: " + ex.Message);
                                Environment.Exit(1);
                            }
                            break;
                        case 2:
                            payload = arg;
                            break;
                        default:
                            Console.WriteLine("Unexpected argument: " + arg);
                            break;
                    }
                    index++;
                }
            }

            if (method == null || uri == null)
                PrintUsage();

            Request request;

            if (uri.Scheme=="coaps") request = NewRequest(method, true);
            else request = NewRequest(method, false);

            if (request == null)
            {
                Console.WriteLine("Unknown method: " + method);
                Environment.Exit(1);
            }

            if ("OBSERVE".Equals(method))
            {
                request.MarkObserve();
                loop = true;
            }
            else if ("DISCOVER".Equals(method) &&
                (String.IsNullOrEmpty(uri.AbsolutePath) || uri.AbsolutePath.Equals("/")))
            {
                uri = new Uri(uri, "/.well-known/core");
            }

            request.URI = uri;
            request.SetPayload(payload, MediaType.TextPlain);

            // uncomment the next line if you want to specify a draft to use
            // request.EndPoint = CoAP.Net.EndPointManager.Draft13;

            Console.WriteLine(Utils.ToString(request));

            try
            {
                if (byEvent)
                {
                    request.Respond += delegate(Object sender, ResponseEventArgs e)
                    {
                        Response response = e.Response;
                        if (response == null)
                        {
                            Console.WriteLine("Request timeout");
                        }
                        else
                        {
                            Console.WriteLine(Utils.ToString(response));
                            Console.WriteLine("Time (ms): " + response.RTT);
                        }
                        if (!loop)
                            Environment.Exit(0);
                    };
                    request.Send();
                    while (true)
                    {
                        Console.ReadKey();
                    }
                }
                else
                {
                    // uncomment the next line if you need retransmission disabled.
                    // request.AckTimeout = -1;

                    request.Send();

                    do
                    {
                        Console.WriteLine("Receiving response...");

                        Response response = null;
                        response = request.WaitForResponse();

                        if (response == null)
                        {
                            Console.WriteLine("Request timeout");
                            break;
                        }
                        else
                        {
                            Console.WriteLine(Utils.ToString(response));
                            Console.WriteLine("Time elapsed (ms): " + response.RTT);

                            if (response.ContentType == MediaType.ApplicationLinkFormat)
                            {
                                IEnumerable<WebLink> links = LinkFormat.Parse(response.PayloadString);
                                if (links == null)
                                {
                                    Console.WriteLine("Failed parsing link format");
                                    Environment.Exit(1);
                                }
                                else
                                {
                                    Console.WriteLine("Discovered resources:");
                                    foreach (var link in links)
                                    {
                                        Console.WriteLine(link);
                                    }
                                }
                            }
                        }
                    } while (loop);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed executing request: " + ex.Message);
                Console.WriteLine(ex);
                Environment.Exit(1);
            }
        }

        private static Request NewRequest(String method, bool Secure)
        {
            switch (method)
            {
                case "POST":
                    if (Secure) return new Request(Method.POST, SecureIdentity, SecureKey, SecureCipher);
                    else return new Request(Method.POST);
                case "PUT":
                    if (Secure) return new Request(Method.PUT, SecureIdentity, SecureKey, SecureCipher);
                    else return new Request(Method.PUT);
                case "DELETE":
                    if (Secure) return new Request(Method.DELETE, SecureIdentity, SecureKey, SecureCipher);
                    else return new Request(Method.DELETE);
                case "GET":
                case "DISCOVER":
                case "OBSERVE":
                    if (Secure) return new Request(Method.GET, SecureIdentity, SecureKey, SecureCipher);
                    else return new Request(Method.GET);
                default:
                    return null;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("CoAP.NET Example Client");
            Console.WriteLine();
            Console.WriteLine("Usage: CoAPClient [-e] [-l] method uri [payload]");
            Console.WriteLine("  method  : { GET, POST, PUT, DELETE, DISCOVER, OBSERVE }");
            Console.WriteLine("  uri     : The CoAP URI of the remote endpoint or resource.");
            Console.WriteLine("  payload : The data to send with the request.");
            Console.WriteLine("Options:");
            Console.WriteLine("  -e      : Receives responses by the Responded event.");
            Console.WriteLine("  -l      : Loops for multiple responses.");
            Console.WriteLine("            (automatic for OBSERVE and separate responses)");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  CoAPClient DISCOVER coap://localhost");
            Console.WriteLine("  CoAPClient POST coap://localhost/storage data");
            Environment.Exit(0);
        }
    }
}
