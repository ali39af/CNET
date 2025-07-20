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

            // CONFIG STUFF
            Config ServerConfig = new("config.conf");


            // DATABASE STUFF
            bool DatabaseIsNew = !File.Exists(AppDbContext.DataSource);
            using (AppDbContext context = new())
            {
                context.Database.EnsureCreated();

                if (DatabaseIsNew)
                {
                    Console.Write("Inserting Default Data ");
                    try
                    {
                        var adsBlacklist = new HashSet<string>(
                                                File.ReadAllLines(Path.Combine(Environment.CurrentDirectory, "data", "ads.txt"))
                                                    .Select(line => line.Trim())
                                                    .Where(line => !string.IsNullOrWhiteSpace(line))
                                            );

                        var nsfwBlacklist = new HashSet<string>(
                            File.ReadAllLines(Path.Combine(Environment.CurrentDirectory, "data", "nsfw.txt"))
                                .Select(line => line.Trim())
                                .Where(line => !string.IsNullOrWhiteSpace(line))
                        );

                        var scamBlacklist = new HashSet<string>(
                            File.ReadAllLines(Path.Combine(Environment.CurrentDirectory, "data", "scam.txt"))
                                .Select(line => line.Trim())
                                .Where(line => !string.IsNullOrWhiteSpace(line))
                        );


                        var proxyList = new HashSet<string>(
                            File.ReadAllLines(Path.Combine(Environment.CurrentDirectory, "data", "proxy-list.txt"))
                                .Select(line => line.Trim())
                                .Where(line => !string.IsNullOrWhiteSpace(line))
                        );

                        foreach (var domain in adsBlacklist)
                        {
                            context.Domains.Add(new Domain { Match = domain, Type = DomainType.Ads });
                        }

                        foreach (var domain in nsfwBlacklist)
                        {
                            context.Domains.Add(new Domain { Match = domain, Type = DomainType.NSFW });
                        }

                        foreach (var domain in scamBlacklist)
                        {
                            context.Domains.Add(new Domain { Match = domain, Type = DomainType.Scam });
                        }


                        foreach (var domain in proxyList)
                        {
                            context.Domains.Add(new Domain { Match = domain, Type = DomainType.Proxy });
                        }

                        context.SaveChanges();
                    }
                    catch (Exception)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[FAILED]");
                    }
                    finally
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[INSERTED]");
                    }
                }
            }

            bool oneServiceFailed = false;

            // DNS SERVICE STUFF
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Starting DNS Service ");

            DNSServer dnsServer = new(ServerConfig);

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
                oneServiceFailed = true;
            }


            // ROUTER STUFF
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Starting Router Service ");
            Router routerServer = new(ServerConfig);

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
                oneServiceFailed = true;
            }


            Console.ForegroundColor = ConsoleColor.White;
            if (!oneServiceFailed)
            {
                Console.WriteLine("All Services Started Successfully!");
            }
            else
            {
                Console.WriteLine("Services Not Fully Functional!!!");
            }

            Thread.Sleep(Timeout.Infinite);

        }

    }
}