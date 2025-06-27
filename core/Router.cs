using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using CNET.Core;

namespace CNET
{
    public class Router
    {
        public ulong ProxyActiveConnections = 0;
        public ulong ProxyCurrentInputBytes = 0;
        public ulong ProxyCurrentOutputBytes = 0;

        private readonly IPEndPoint _bindingHTTPAddress;
        private readonly IPEndPoint _bindingHTTPSAddress;
        private readonly Blacklist _blacklist;
        private readonly HashSet<string> _proxyList;
        private readonly HashSet<IPAddress> _allowedIPs;
        private TcpListener _httpListener;
        private TcpListener _httpsListener;
        private CancellationTokenSource _cts;
        private Timer _statsResetTimer;
        private DNSClient _dnsClient;
        private IgnoreWarningCache _ignoreWarningCache;
        private readonly bool _proxyOnlyWhenLogin;
        private LoginCache _loginCache;
        private readonly string _Login;
        private readonly string _ADS;
        private readonly string _NSFW;
        private readonly string _SCAM;

        public Router(IPEndPoint bindingHTTPAddress, IPEndPoint bindingHTTPSAddress, Blacklist blacklist, HashSet<string> proxyList, DNSClient dnsClient, IgnoreWarningCache ignoreWarningCache, HashSet<IPAddress> allowedIPs, bool proxyOnlyWhenLogin, LoginCache loginCache)
        {
            _bindingHTTPAddress = bindingHTTPAddress;
            _bindingHTTPSAddress = bindingHTTPSAddress;
            _blacklist = blacklist;
            _proxyList = proxyList;
            _dnsClient = dnsClient;
            _ignoreWarningCache = ignoreWarningCache;
            _allowedIPs = allowedIPs;
            _proxyOnlyWhenLogin = proxyOnlyWhenLogin;
            _loginCache = loginCache;

            var assembly = Assembly.GetExecutingAssembly();


            using (Stream stream = assembly.GetManifestResourceStream("CNET.wwwroot.Login.html"))
            {
                if (stream == null)
                {
                    Console.WriteLine("ADS Resource not found.");
                    _Login = string.Empty;
                }
                else
                {
                    using StreamReader reader = new StreamReader(stream);
                    _Login = reader.ReadToEnd();
                }
            }

            using (Stream stream = assembly.GetManifestResourceStream("CNET.wwwroot.ADS.html"))
            {
                if (stream == null)
                {
                    Console.WriteLine("ADS Resource not found.");
                    _ADS = string.Empty;
                }
                else
                {
                    using StreamReader reader = new StreamReader(stream);
                    _ADS = reader.ReadToEnd();
                }
            }

            using (Stream stream = assembly.GetManifestResourceStream("CNET.wwwroot.NSFW.html"))
            {
                if (stream == null)
                {
                    Console.WriteLine("NSFW Resource not found.");
                    _NSFW = string.Empty;
                }
                else
                {
                    using StreamReader reader = new StreamReader(stream);
                    _NSFW = reader.ReadToEnd();
                }
            }

            using (Stream stream = assembly.GetManifestResourceStream("CNET.wwwroot.SCAM.html"))
            {
                if (stream == null)
                {
                    Console.WriteLine("SCAM Resource not found.");
                    _SCAM = string.Empty;
                }
                else
                {
                    using StreamReader reader = new StreamReader(stream);
                    _SCAM = reader.ReadToEnd();
                }
            }

        }

        public void Start()
        {
            _cts = new CancellationTokenSource();

            _httpListener = new TcpListener(_bindingHTTPAddress);
            _httpsListener = new TcpListener(_bindingHTTPSAddress);

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
                if (remoteEndPoint != null && _allowedIPs.Count > 0 && !_allowedIPs.Contains(remoteEndPoint.Address))
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
                        await RedirectToCaptivatePortal(stream);
                        return;
                    }

                    if (DNSServer.CaptivePortalDomain == host)
                    {
                        var parts = requestLine.Split(' ');
                        if (parts.Length >= 2)
                        {
                            string method = parts[0];
                            string path = parts[1];


                            if (method.Equals("POST", StringComparison.OrdinalIgnoreCase) && path.Equals("/login", StringComparison.OrdinalIgnoreCase))
                            {
                                for (int i = 0; i < 3; i++)
                                {
                                    await reader.ReadLineAsync();
                                }
                                string password = (await reader.ReadLineAsync()).Split(':')[1].Trim();
                                string username = (await reader.ReadLineAsync()).Split(':')[1].Trim();

                                const string validUsername = "ucnet";
                                const string validPassword = "1234567890";

                                if (string.Equals(username, validUsername, StringComparison.Ordinal) &&
                                    string.Equals(password, validPassword, StringComparison.Ordinal))
                                {
                                    if (remoteEndPoint != null)
                                    {
                                        _loginCache.Add(remoteEndPoint.Address);
                                    }

                                    string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                                    byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                                    await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
                                }
                                else
                                {
                                    string response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
                                    byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                                    await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
                                }

                                return;
                            }

                        }

                        await SendLoginPageAsync(stream);
                        return;
                    }

                    var (blocked, type) = _blacklist.Exist(host);
                    if (blocked)
                    {
                        var parts = requestLine.Split(' ');
                        if (parts.Length >= 2)
                        {
                            string method = parts[0];
                            string path = parts[1];

                            if (method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
                                path.Equals("/ignore", StringComparison.OrdinalIgnoreCase))
                            {
                                if (remoteEndPoint != null)
                                {
                                    _ignoreWarningCache.Add(host, remoteEndPoint.Address);
                                }

                                string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                                byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                                await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
                                return;
                            }
                        }

                        if (!(remoteEndPoint != null && _ignoreWarningCache.Contains(host, remoteEndPoint.Address)))
                        {
                            await SendBlockPageAsync(stream, type);
                            return;
                        }
                    }

                    if (_proxyOnlyWhenLogin && !_loginCache.Contains(remoteEndPoint.Address))
                        return;

                    if (IsInList.Exist(_proxyList, host))
                        await ProxyTcpAsync(client, host, 80, initialData);
                }
                catch { }
            }
        }

        private async Task HandleHttpsConnection(TcpClient client)
        {
            using (client)
            {
                IPEndPoint? remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                if (remoteEndPoint != null && _allowedIPs.Count > 0 && !_allowedIPs.Contains(remoteEndPoint.Address))
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

                var (blocked, type) = _blacklist.Exist(sni);
                if (blocked)
                {
                    if (!(remoteEndPoint != null && _ignoreWarningCache.Contains(sni, remoteEndPoint.Address)))
                    {
                        return;
                    }
                }

                if (_proxyOnlyWhenLogin && !_loginCache.Contains(remoteEndPoint.Address))
                    return;

                if (IsInList.Exist(_proxyList, sni))
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

        private async Task SendBlockPageAsync(NetworkStream stream, BlacklistType type)
        {
            string html = type == BlacklistType.NSFW ? _NSFW : type == BlacklistType.ADS ? _ADS : _SCAM;
            string response = $"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(html)}\r\n\r\n{html}";
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(bytes);
        }

        private async Task SendLoginPageAsync(NetworkStream stream)
        {
            string response = $"HTTP/1.1 200 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(_Login)}\r\n\r\n{_Login}";
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(bytes);
        }

        private async Task RedirectToCaptivatePortal(NetworkStream stream)
        {
            string response = $"HTTP/1.1 302 Found\r\nLocation: http://{DNSServer.CaptivePortalDomain}\r\nContent-Length: 0\r\n\r\n";
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(bytes);
        }

        private string ExtractSNIFromClientHello(byte[] data)
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
