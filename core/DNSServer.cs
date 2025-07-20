// TODO Find Match domain from Domains in Database without Fetch all and Search

using System.Net;
using System.Net.Sockets;

namespace CNET.Core
{
    public class DNSServer
    {
        private readonly Config _config;
        public static readonly HashSet<string> CaptivePortalDomains = new()
        {
            "connectivitycheck.gstatic.com",
            "clients1.google.com",
            "clients2.google.com",
            "clients3.google.com",
            "clients4.google.com",
            "clients5.google.com",
            "connectivitycheck.android.com",
            "captive.apple.com",
            "www.apple.com",
            "www.msftconnecttest.com",
            "msftconnecttest.com",
            "msftncsi.com",
            "ipv6.msftconnecttest.com",
            "ipv6.msftncsi.com",
            "detectportal.firefox.com",
            "connectivity-check.ubuntu.com",
            "network-test.debian.org",
            "start.ubuntu.com",
            "neverssl.com",
            "kindle-wifi.amazon.com",
            "a.rvd.nokia.com",
            "walledgarden.com"
        };

        private UdpClient? _udpServer;
        private CancellationTokenSource? _cts;

        public DNSServer(Config config)
        {
            _config = config;
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _udpServer = new UdpClient(_config.DnsBindEndpoint);

            var token = _cts.Token;

            ThreadPool.QueueUserWorkItem(_ =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        IPEndPoint client = new(IPAddress.Loopback, 0);
                        byte[] req = _udpServer.Receive(ref client);

                        if (_config.AllowedIPs.Count > 0 && !CidrMatcher.IsIpInCidrList(_config.AllowedIPs, client.Address.ToString()))
                        {
                            return;
                        }

                        ThreadPool.QueueUserWorkItem(__ => ProcessRequest(req, client));
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                    {
                        if (token.IsCancellationRequested)
                            break;
                    }
                    catch (ObjectDisposedException)
                    {
                        if (token.IsCancellationRequested)
                            break;
                    }
                    catch (Exception) { }
                }
            });

        }

        public void Stop()
        {
            _cts?.Cancel();
            _udpServer?.Close();
            _udpServer?.Dispose();
            _cts?.Dispose();
            _cts = null;
        }

        private void ProcessRequest(byte[] req, IPEndPoint client)
        {
            try
            {
                string domain = ExtractDomain(req);
                bool isBlocked = false;
                bool isInProxyList = false;
                DomainType ResultType;
                if (CacheDatabase.Instance.TryGetRecent(domain, out ResultType))
                {
                    if (ResultType == DomainType.Proxy)
                    {
                        isInProxyList = true;
                    }
                    else
                    {
                        isBlocked = true;
                    }
                }
                else
                {
                    using (AppDbContext context = new())
                    {
                        List<Domain> domains = context.Domains.ToList(); // need make this global or something more efficient
                        Domain searchResult = domains.Find(_domain => WildcardMatcher.IsMatch(_domain.Match, domain));
                        if (searchResult != null)
                        {
                            CacheDatabase.Instance.SetRecent(domain, searchResult.Type);
                            if (searchResult.Type == DomainType.Proxy)
                            {
                                isInProxyList = true;
                            }
                            else
                            {
                                isBlocked = true;
                            }
                        }
                    }
                }

                var type = GetQueryType(req);

                if (isBlocked)
                    isBlocked = !CacheDatabase.Instance.ContainsIgnore(domain, client.Address);


                bool isRedirected = (isBlocked || isInProxyList) && (type == QueryType.A || type == QueryType.AAAA);

                if (CaptivePortalDomains.Contains(domain) && !CacheDatabase.Instance.ContainsLogin(client.Address))
                {
                    isRedirected = true;
                }

                if (_config.CaptivatePortalDomain == domain)
                    isRedirected = true;


                if (_config.CaptivatePortalPanelDomain == domain)
                    isRedirected = true;

#if DEBUG
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"[DNS] {(isRedirected ? "Redirected" : "Forwarded")} {type} {domain} From {client}");
#endif


                byte[] res = isRedirected
                    ? CreateLocalResponse(req)
                    : ForwardRequest(req);

                _udpServer?.Send(res, res.Length, client);
            }
            catch
            {
                try
                {
                    var err = CreateErrorResponse(req);
                    _udpServer?.Send(err, err.Length, client);
                }
                catch { }
            }
        }

        private string ExtractDomain(byte[] req)
        {
            if (req.Length < 12) return "unknown";

            var name = new List<string>();
            int i = 12;

            while (i < req.Length && req[i] != 0)
            {
                int len = req[i++];
                if (i + len > req.Length) break;
                name.Add(System.Text.Encoding.ASCII.GetString(req, i, len));
                i += len;
            }

            return string.Join('.', name);
        }

        private enum QueryType : ushort
        {
            Unknown = 0,
            A = 1,
            AAAA = 28,
            CNAME = 5,
            MX = 15,
            TXT = 16
        }

        private QueryType GetQueryType(byte[] req)
        {
            int i = 12;
            while (i < req.Length && req[i] != 0)
            {
                if (i + req[i] >= req.Length) return QueryType.Unknown;
                i += req[i] + 1;
            }

            i++;
            if (i + 4 > req.Length) return QueryType.Unknown;

            ushort qtype = (ushort)((req[i] << 8) | req[i + 1]);
            return Enum.IsDefined(typeof(QueryType), qtype) ? (QueryType)qtype : QueryType.Unknown;
        }

        private byte[] CreateLocalResponse(byte[] req, int ttl = 60)
        {
            using var ms = new MemoryStream();
            ms.Write(req, 0, 12);

            ms.Position = 2;
            ms.WriteByte(0x81);
            ms.WriteByte(0x80);

            ms.Position = 6;
            ms.Write([0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

            int qEnd = 12;
            while (qEnd < req.Length && req[qEnd] != 0)
                qEnd += req[qEnd] + 1;
            qEnd += 5;

            ms.Write(req, 12, qEnd - 12);

            bool isAAAA = ((req[qEnd - 4] << 8) | req[qEnd - 3]) == 28;
            byte[] ip = isAAAA ? _config.RouterIPV6.GetAddressBytes() : _config.RouterIPV4.GetAddressBytes();

            ms.Write([
                0xC0, 0x0C,
        req[qEnd - 4], req[qEnd - 3],
        0x00, 0x01,
        (byte)((ttl >> 24) & 0xFF),
        (byte)((ttl >> 16) & 0xFF),
        (byte)((ttl >> 8) & 0xFF),
        (byte)(ttl & 0xFF),
        0x00, (byte)ip.Length
            ]);
            ms.Write(ip, 0, ip.Length);

            return ms.ToArray();
        }


        private byte[] CreateErrorResponse(byte[] req)
        {
            var res = new byte[Math.Min(req.Length, 12)];
            Array.Copy(req, res, res.Length);

            if (res.Length >= 3)
            {
                res[2] = 0x81;
                res[3] = 0x82;
            }

            return res;
        }

        private byte[] ForwardRequest(byte[] req)
        {
            try
            {
                using var client = new UdpClient();
                client.Client.ReceiveTimeout = 1900;
                client.Connect(_config.ForwardDnsEndpoint);
                client.Send(req, req.Length);

                IPEndPoint ep = new(IPAddress.Any, 0);
                return client.Receive(ref ep);
            }
            catch
            {
                return CreateErrorResponse(req);
            }
        }
    }
}
