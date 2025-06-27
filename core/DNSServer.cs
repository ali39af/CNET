using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace CNET.Core
{
    public class DNSServer
    {
        private readonly IPAddress _webIPv4;
        private readonly IPAddress _webIPv6;
        private readonly IPEndPoint _forwardDns;
        private readonly Blacklist _blacklist;
        private readonly HashSet<string> _proxyList;
        private readonly IPEndPoint _bindingAddress;
        private readonly HashSet<IPAddress> _allowedIPs;
        private readonly bool _proxyOnlyWhenLogin;
        public static readonly string CaptivePortalDomain = "cnet.net";
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

        private IgnoreWarningCache _ignoreWarningCache;
        private LoginCache _loginCache;
        private UdpClient? _udpServer;
        private CancellationTokenSource? _cts;

        public DNSServer(IPEndPoint bindingAddress, Blacklist blacklist, HashSet<string> proxyList, IPEndPoint forwardDns, IPAddress webIPv4, IPAddress webIPv6, IgnoreWarningCache ignoreWarningCache, HashSet<IPAddress> allowedIPs, bool proxyOnlyWhenLogin, LoginCache loginCache)
        {
            _bindingAddress = bindingAddress;
            _blacklist = blacklist;
            _proxyList = proxyList;
            _forwardDns = forwardDns;
            _webIPv4 = webIPv4;
            _webIPv6 = webIPv6;
            _ignoreWarningCache = ignoreWarningCache;
            _allowedIPs = allowedIPs;
            _proxyOnlyWhenLogin = proxyOnlyWhenLogin;
            _loginCache = loginCache;
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _udpServer = new UdpClient(_bindingAddress);

            var token = _cts.Token;

            ThreadPool.QueueUserWorkItem(_ =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        IPEndPoint client = new(IPAddress.Loopback, 0);
                        byte[] req = _udpServer.Receive(ref client);

                        if (_allowedIPs.Count > 0 && !_allowedIPs.Contains(client.Address))
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
                var (isBlocked, _) = _blacklist.Exist(domain);
                var type = GetQueryType(req);

                if (isBlocked)
                    isBlocked = !_ignoreWarningCache.Contains(domain, client.Address);

                bool isInProxyList = !isBlocked ? IsInList.Exist(_proxyList, domain) : false;

                bool isRedirected = (isBlocked && (type == QueryType.A || type == QueryType.AAAA)) || isInProxyList;

                if (CaptivePortalDomains.Contains(domain) && !_loginCache.Contains(client.Address))
                {
                    isRedirected = true;
                    isBlocked = true; // just for now for ttl 1sec on next version we clean up here
                }

                if (CaptivePortalDomain == domain)
                    isRedirected = true;

#if DEBUG
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"[DNS] {(isRedirected ? "Redirected" : "Forwarded")} {type} {domain} From {client}");
#endif


                byte[] res = isRedirected
                    ? CreateLocalResponse(req, isBlocked ? 1 : 30)
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

        private byte[] CreateLocalResponse(byte[] req, int ttl = 30)
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
            byte[] ip = isAAAA ? _webIPv6.GetAddressBytes() : _webIPv4.GetAddressBytes();

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
                client.Connect(_forwardDns);
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
