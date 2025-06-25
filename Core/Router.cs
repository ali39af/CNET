using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

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

        private TcpListener _httpListener;
        private TcpListener _httpsListener;
        private CancellationTokenSource _cts;
        private Timer _statsResetTimer;

        public Router(IPEndPoint bindingHTTPAddress, IPEndPoint bindingHTTPSAddress, Blacklist blacklist, HashSet<string> proxyList)
        {
            _bindingHTTPAddress = bindingHTTPAddress;
            _bindingHTTPSAddress = bindingHTTPSAddress;
            _blacklist = blacklist;
            _proxyList = proxyList;
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
                var stream = client.GetStream();
                var reader = new StreamReader(stream, leaveOpen: true);
                var writer = new StreamWriter(stream) { AutoFlush = true };

                try
                {
                    string requestLine = await reader.ReadLineAsync();
                    if (string.IsNullOrEmpty(requestLine)) return;

                    string hostLine = null;
                    while (!string.IsNullOrEmpty(hostLine = await reader.ReadLineAsync()))
                    {
                        if (hostLine.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                            break;
                    }

                    if (hostLine == null) return;
                    string host = hostLine.Substring(5).Trim();

#if DEBUG
                    IPEndPoint? remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                    if (remoteEndPoint != null)
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"[Router] HTTP {host} from {remoteEndPoint.Address}");
                        Console.ResetColor();
                    }
#endif

                    var (blocked, type) = _blacklist.Exist(host);
                    if (blocked)
                    {
                        await SendBlockPageAsync(stream, host, type);
                        return;
                    }

                    if (IsInProxyList(host))
                        await ProxyTcpAsync(client, host, 80, null);
                }
                catch { }
            }
        }

        private async Task HandleHttpsConnection(TcpClient client)
        {
            using (client)
            {
                var stream = client.GetStream();
                var buffer = new byte[1024];
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0) return;

                string sni = ExtractSNIFromClientHello(buffer);
                if (sni == null) return;

#if DEBUG
                IPEndPoint? remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                if (remoteEndPoint != null)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine($"[Router] HTTPS {sni} from {remoteEndPoint.Address}");
                    Console.ResetColor();
                }
#endif

                var (blocked, _) = _blacklist.Exist(sni);
                if (blocked)
                {
                    await SendHttpsRedirectAsync(stream, sni);
                    return;
                }

                if (IsInProxyList(sni))
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
                await target.ConnectAsync(host, port);
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

        private async Task SendBlockPageAsync(NetworkStream stream, string domain, BlacklistType type)
        {
            string html = $"<html><body><h1>Blocked: {type}</h1><p>{domain} is restricted.</p></body></html>";
            string response = $"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(html)}\r\n\r\n{html}";
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(bytes);
        }

        private async Task SendHttpsRedirectAsync(NetworkStream stream, string domain)
        {
            string html = $"<html><body><h1>Blocked (HTTPS)</h1><p>{domain} is redirected due to security policy.</p></body></html>";
            string response = $"HTTP/1.1 302 Found\r\nLocation: http://{domain}/blocked\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(html)}\r\n\r\n{html}";
            byte[] bytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(bytes);
        }

        private bool IsInProxyList(string domain)
        {
            foreach (var pattern in _proxyList)
            {
                if (pattern == "*") return true;
                string regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
                if (Regex.IsMatch(domain, regex, RegexOptions.IgnoreCase))
                    return true;
            }
            return false;
        }

        private string ExtractSNIFromClientHello(byte[] data)
        {
            try
            {
                int pos = 0;
                if (data[0] != 0x16) return null;
                pos += 5; // skip record header
                pos += 34; // skip handshake + random

                int sessionIDLen = data[pos];
                pos += 1 + sessionIDLen;

                int cipherLen = (data[pos] << 8) + data[pos + 1];
                pos += 2 + cipherLen;

                int compLen = data[pos];
                pos += 1 + compLen;

                int extLen = (data[pos] << 8) + data[pos + 1];
                pos += 2;

                int end = pos + extLen;

                while (pos + 4 <= end)
                {
                    int type = (data[pos] << 8) + data[pos + 1];
                    int len = (data[pos + 2] << 8) + data[pos + 3];
                    pos += 4;

                    if (type == 0x00 && len > 5)
                    {
                        int sniLen = (data[pos + 2] << 8) + data[pos + 3];
                        return Encoding.ASCII.GetString(data, pos + 5, sniLen);
                    }

                    pos += len;
                }
            }
            catch { }
            return null;
        }
    }
}
