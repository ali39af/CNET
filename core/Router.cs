// TODO Add Counter for Each user traffic
// TODO Fix huge EFCore Query ToList

using System.Net;
using System.Net.Sockets;
using System.Text;
using CNET.Core;

namespace CNET
{
    public class Router
    {
        public ulong ProxyActiveConnections = 0;
        public ulong ProxyCurrentInputBytes = 0;
        public ulong ProxyCurrentOutputBytes = 0;

        private TcpListener _httpListener;
        private TcpListener _httpsListener;
        private CancellationTokenSource _cts;
        private Timer _statsResetTimer;
        private DNSClient _dnsClient;
        private readonly Config _config;
        private BlockerWebApp _nsfwWebApp;
        private BlockerWebApp _scamWebApp;
        private BlockerWebApp _adsWebApp;
        private HotspotPortalWebApp _hotspotPortalWebApp;
        private HotspotPanelWebApp _hotspotPanelWebApp;

        public Router(Config config)
        {
            _config = config;

            _dnsClient = new(_config.ForwardDnsEndpoint);

            _nsfwWebApp = new(DomainType.NSFW);
            _nsfwWebApp.config = _config;
            _scamWebApp = new(DomainType.Scam);
            _scamWebApp.config = _config;
            _adsWebApp = new(DomainType.Ads);
            _adsWebApp.config = _config;

            _hotspotPortalWebApp = new();
            _hotspotPortalWebApp.config = _config;

            _hotspotPanelWebApp = new();
            _hotspotPanelWebApp.config = _config;
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();

            _httpListener = new TcpListener(_config.HttpBindEndpoint);
            _httpsListener = new TcpListener(_config.HttpsBindEndpoint);

            _httpListener.Start();
            _httpsListener.Start();

            Task.Run(() => AcceptLoop(_httpListener, HandleHttpConnection, _cts.Token));
            Task.Run(() => AcceptLoop(_httpsListener, HandleHttpsConnection, _cts.Token));

            _statsResetTimer = new Timer(_ =>
            {
                Interlocked.Exchange(ref ProxyCurrentInputBytes, 0);
                Interlocked.Exchange(ref ProxyCurrentOutputBytes, 0);
            }, null, 1000, 1000);
        }

        public void Stop()
        {
            _cts.Cancel();
            _httpListener.Stop();
            _httpsListener.Stop();
            _statsResetTimer.Dispose();
        }

        private async Task AcceptLoop(TcpListener listener, Func<TcpClient, Task> handler, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var client = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => handler(client));
                }
                catch { }
            }
        }

        private async Task HandleHttpConnection(TcpClient client)
        {
            using (client)
            {
                IPEndPoint? remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                if (remoteEndPoint != null && _config.AllowedIPs.Count > 0 && !CidrMatcher.IsIpInCidrList(_config.AllowedIPs, remoteEndPoint.Address.ToString()))
                {
                    return;
                }
                var stream = client.GetStream();
                var reader = new StreamReader(stream, leaveOpen: true);
                var writer = new StreamWriter(stream) { AutoFlush = true };

                try
                {
                    string requestLine = await reader.ReadLineAsync();
                    if (string.IsNullOrEmpty(requestLine)) return;

                    var requestBuilder = new StringBuilder();
                    requestBuilder.AppendLine(requestLine);

                    string hostLine = null;
                    while (!string.IsNullOrEmpty(hostLine = await reader.ReadLineAsync()))
                    {
                        requestBuilder.AppendLine(hostLine);
                        if (hostLine.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                            break;
                    }

                    requestBuilder.AppendLine();

                    byte[] initialData = Encoding.ASCII.GetBytes(requestBuilder.ToString());

                    if (hostLine == null) return;
                    string host = hostLine.Substring(5).Trim();

#if DEBUG
                    if (remoteEndPoint != null)
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"[Router] HTTP {host} from {remoteEndPoint.Address}");
                        Console.ResetColor();
                    }
#endif

                    if (DNSServer.CaptivePortalDomains.Contains(host))
                    {
                        await RedirectTo(stream, $"http://{_config.CaptivatePortalDomain}");
                        return;
                    }

                    if (_config.CaptivatePortalPanelDomain == host)
                    {
                        _hotspotPanelWebApp.ProcessRequest(initialData, reader, writer, client);
                        return;
                    }



                    if (_config.CaptivatePortalDomain == host)
                    {
                        _hotspotPortalWebApp.ProcessRequest(initialData, reader, writer, client);
                        return;
                    }

                    bool isBlocked = false;
                    bool isInProxyList = false;
                    DomainType ResultType;
                    if (CacheDatabase.Instance.TryGetRecent(host, out ResultType))
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
                            Domain searchResult = domains.Find(_domain => WildcardMatcher.IsMatch(_domain.Match, host));
                            if (searchResult != null)
                            {
                                CacheDatabase.Instance.SetRecent(host, searchResult.Type);
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
                    if (isBlocked && !(remoteEndPoint != null && CacheDatabase.Instance.ContainsIgnore(host, remoteEndPoint.Address)))
                    {
                        switch (ResultType)
                        {
                            case DomainType.NSFW:
                                _nsfwWebApp.ProcessRequest(initialData, reader, writer, client);
                                break;
                            case DomainType.Scam:
                                _scamWebApp.ProcessRequest(initialData, reader, writer, client);
                                break;
                            case DomainType.Ads:
                                _adsWebApp.ProcessRequest(initialData, reader, writer, client);
                                break;
                        }
                        return;
                    }

                    if (_config.CaptivatePortal && !CacheDatabase.Instance.ContainsLogin(remoteEndPoint.Address))
                        return;

                    if (isInProxyList)
                        await ProxyTcpAsync(client, host, 80, initialData);
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine(e);
#endif
                }
            }
        }

        private async Task HandleHttpsConnection(TcpClient client)
        {
            using (client)
            {
                IPEndPoint? remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                if (remoteEndPoint != null && _config.AllowedIPs.Count > 0 && !CidrMatcher.IsIpInCidrList(_config.AllowedIPs, remoteEndPoint.Address.ToString()))
                {
                    return;
                }
                var stream = client.GetStream();
                var buffer = new byte[1024];
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0) return;

                string sni = ExtractSNIFromClientHello(buffer);
                if (sni == null) return;

#if DEBUG
                if (remoteEndPoint != null)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine($"[Router] HTTPS {sni} from {remoteEndPoint.Address}");
                    Console.ResetColor();
                }
#endif

                bool isBlocked = false;
                bool isInProxyList = false;
                DomainType ResultType;
                if (CacheDatabase.Instance.TryGetRecent(sni, out ResultType))
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
                        Domain searchResult = domains.Find(_domain => WildcardMatcher.IsMatch(_domain.Match, sni));
                        if (searchResult != null)
                        {
                            CacheDatabase.Instance.SetRecent(sni, searchResult.Type);
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
                if (isBlocked)
                {
                    if (!(remoteEndPoint != null && CacheDatabase.Instance.ContainsIgnore(sni, remoteEndPoint.Address)))
                    {
                        return;
                    }
                }

                if (_config.CaptivatePortal && !CacheDatabase.Instance.ContainsLogin(remoteEndPoint.Address))
                    return;

                if (isInProxyList)
                    await ProxyTcpAsync(client, sni, 443, buffer[..read]);
            }
        }

        private async Task ProxyTcpAsync(TcpClient client, string host, int port, byte[] initialData)
        {
#if DEBUG
            IPEndPoint? remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
            if (remoteEndPoint != null)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"[Router] Proxying from {remoteEndPoint.Address} to {host}");
                Console.ResetColor();
            }
#endif
            using var target = new TcpClient();
            try
            {
                await target.ConnectAsync(await _dnsClient.ResolveAAsync(host), port);
                using var clientStream = client.GetStream();
                using var targetStream = target.GetStream();

                if (initialData != null)
                    await targetStream.WriteAsync(initialData);

                Interlocked.Increment(ref ProxyActiveConnections);

                var cts = new CancellationTokenSource();

                var clientToTarget = PumpAsync(clientStream, targetStream, true, cts.Token);
                var targetToClient = PumpAsync(targetStream, clientStream, false, cts.Token);

                await Task.WhenAny(clientToTarget, targetToClient);
                cts.Cancel();
            }
            catch { }
            finally
            {
                Interlocked.Decrement(ref ProxyActiveConnections);
            }
        }

        private async Task PumpAsync(Stream from, Stream to, bool isInput, CancellationToken ct)
        {
            var buffer = new byte[8192];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    int bytesRead = await from.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                    if (bytesRead <= 0) break;

                    await to.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
                    if (isInput)
                        Interlocked.Add(ref ProxyCurrentInputBytes, (ulong)bytesRead);
                    else
                        Interlocked.Add(ref ProxyCurrentOutputBytes, (ulong)bytesRead);
                }
            }
            catch { }
        }

        private async Task RedirectTo(NetworkStream stream, string address)
        {
            string response = $"HTTP/1.1 302 Found\r\nLocation: {address}\r\nContent-Length: 0\r\n\r\n";
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(bytes);
        }

        private string? ExtractSNIFromClientHello(byte[] data)
        {
            try
            {
                int pos = 0;

                if (data[0] != 0x16)
                    return null;

                pos += 5;
                if (data[pos] != 0x01)
                    return null;

                pos += 4;

                pos += 2;
                pos += 32;

                int sessionIdLength = data[pos];
                pos += 1 + sessionIdLength;

                int cipherSuitesLength = (data[pos] << 8) | data[pos + 1];
                pos += 2 + cipherSuitesLength;

                int compressionMethodsLength = data[pos];
                pos += 1 + compressionMethodsLength;

                int extensionsLength = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                int extensionsEnd = pos + extensionsLength;

                while (pos + 4 <= extensionsEnd)
                {
                    int extensionType = (data[pos] << 8) | data[pos + 1];
                    int extensionLength = (data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;

                    if (extensionType == 0x00)
                    {
                        int sniListLength = (data[pos] << 8) | data[pos + 1];
                        int sniType = data[pos + 2];
                        int sniNameLength = (data[pos + 3] << 8) | data[pos + 4];

                        if (sniType != 0x00) return null;

                        return Encoding.ASCII.GetString(data, pos + 5, sniNameLength);
                    }

                    pos += extensionLength;
                }
            }
            catch
            { }

            return null;
        }
    }
}
