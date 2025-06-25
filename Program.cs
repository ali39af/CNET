using System.Net;
using CNET.Core;

namespace CNET
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"
  ____   _   _ _____ _____ 
 / ___| | \ | | ____|_   _|
| |     |  \| |  _|   | |  
| |___  | |\  | |___  | |  
 \____| |_| \_|_____| |_|   made by [ali39af]

clean and safe internet for everyone

");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Starting CNET please wait...");

            // Loading and init Blacklist Stuff
            Console.Write("Loading Blacklist Items ");
            HashSet<string> adsBlacklist = new(File.ReadAllText(Path.Join(Environment.CurrentDirectory, "data", "ads.txt")).Split('\n'));
            HashSet<string> nsfwBlacklist = new(File.ReadAllText(Path.Join(Environment.CurrentDirectory, "data", "nsfw.txt")).Split('\n'));
            HashSet<string> scamBlacklist = new(File.ReadAllText(Path.Join(Environment.CurrentDirectory, "data", "scam.txt")).Split('\n'));
            Blacklist blacklist = new(adsBlacklist, nsfwBlacklist, scamBlacklist);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[LOADED]");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"ADS: {adsBlacklist.Count}");
            Console.WriteLine($"NSFW: {nsfwBlacklist.Count}");
            Console.WriteLine($"SCAM: {scamBlacklist.Count}");

            // Loading and init DNSServer Stuff
            Console.Write("Starting DNS Service ");
            DNSServer dnsServer = new(
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 53), // Some times your Any AKA 0.0.0.0 53 port is busy you can chose a specify ip to resolve this issue
                blacklist,
                new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53),
                IPAddress.Parse("127.0.0.1"), // Give Public IPV4 Address WebRouter Service Listen on 443, 80 port 
                IPAddress.Parse("::1") // Give Public IPV6 Address WebRouter Service Listen on 443, 80 port
            );
            try
            {
                dnsServer.Start();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[OK]");
            }
            catch
            {
                dnsServer.Start();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[FAILED]");
            }

            // Loading and init Router Stuff
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Starting Router Service ");
            Router routerServer = new(
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 80),
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 443),
                blacklist,
                new HashSet<string>(["*"])
            );
            try
            {
                routerServer.Start();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[OK]");
            }
            catch
            {
                routerServer.Start();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[FAILED]");
            }
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("All Services Started Successfully!");
            while (true)
            {
                string status = $"Proxy [Active {routerServer.ProxyActiveConnections} Tunnels] [In {routerServer.ProxyCurrentInputBytes}B/Sec] [Out {routerServer.ProxyCurrentOutputBytes}B/Sec]";

                Console.Write("\r" + status.PadRight(Console.WindowWidth - 1));
                Thread.Sleep(1000);
            }

        }
    }
}
