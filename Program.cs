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
            HashSet<string> adsBlacklist = new(File.ReadAllText(Path.Join(Environment.CurrentDirectory, "data", "ads.txt")).Split('\n').Select(line => line.Trim('\r')).ToArray());
            HashSet<string> nsfwBlacklist = new(File.ReadAllText(Path.Join(Environment.CurrentDirectory, "data", "nsfw.txt")).Split('\n').Select(line => line.Trim('\r')).ToArray());
            HashSet<string> scamBlacklist = new(File.ReadAllText(Path.Join(Environment.CurrentDirectory, "data", "scam.txt")).Split('\n').Select(line => line.Trim('\r')).ToArray());
            Blacklist blacklist = new(nsfwBlacklist, adsBlacklist, scamBlacklist);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[LOADED]");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"ADS: {adsBlacklist.Count}");
            Console.WriteLine($"NSFW: {nsfwBlacklist.Count}");
            Console.WriteLine($"SCAM: {scamBlacklist.Count}");

            // Shared Ignore Blacklist Cache

            IgnoreWarningCache sharedIgnoreCache = new();

            // Proxy List Stuff

            HashSet<string> proxyList = new(["*aparat.com", "*nic.ir"]);

            // Loading and init DNSServer Stuff
            Console.Write("Starting DNS Service ");
            DNSServer dnsServer = new(
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 53), // Some times your Any AKA 0.0.0.0 53 port is busy you can chose a specify ip to resolve this issue
                blacklist,
                proxyList,
                new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53),
                IPAddress.Parse("127.0.0.1"), // Give Public IPV4 Address WebRouter Service Listen on 443, 80 port 
                IPAddress.Parse("::1"), // Give Public IPV6 Address WebRouter Service Listen on 443, 80 port
                sharedIgnoreCache
            );
            try
            {
                dnsServer.Start();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[OK]");
            }
            catch
            {
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
                proxyList,
                new DNSClient("8.8.8.8", 53),
                sharedIgnoreCache
            );
            try
            {
                routerServer.Start();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[OK]");
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[FAILED]");
            }
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("All Services Started Successfully!");

            int lastStatusLine = Console.WindowHeight - 1;

            while (true)
            {
                string status = $"Proxy [Active {routerServer.ProxyActiveConnections} Tunnels] [In {FormatBytes.FromULONG(routerServer.ProxyCurrentInputBytes)}/Sec] [Out {FormatBytes.FromULONG(routerServer.ProxyCurrentOutputBytes)}/Sec]";

                int curLeft = Console.CursorLeft;
                int curTop = Console.CursorTop;

                Console.SetCursorPosition(0, lastStatusLine);
                Console.Write(status.PadRight(Console.WindowWidth - 1));

                Console.SetCursorPosition(curLeft, curTop);
                Thread.Sleep(250);
            }
        }

    }
}