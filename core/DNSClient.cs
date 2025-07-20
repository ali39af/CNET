using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CNET
{
    public class DNSClient
    {
        private readonly IPEndPoint _dnsServer;
        private readonly Dictionary<string, CacheEntry> _cache = new Dictionary<string, CacheEntry>();

        public DNSClient(IPEndPoint? dnsServer = null)
        {
            dnsServer ??= new(IPAddress.Parse("8.8.8.8"), 53);
            _dnsServer = dnsServer;
        }

        public async Task<IPAddress[]> ResolveAAsync(string domain)
        {
            return await ResolveAsync(domain, isAAAA: false);
        }

        public async Task<IPAddress[]> ResolveAAAAAsync(string domain)
        {
            return await ResolveAsync(domain, isAAAA: true);
        }

        private async Task<IPAddress[]> ResolveAsync(string domain, bool isAAAA)
        {
            string key = $"{domain}_{(isAAAA ? "AAAA" : "A")}";

            if (_cache.TryGetValue(key, out var entry))
            {
                if (DateTime.UtcNow < entry.ExpireAt)
                    return entry.Addresses;
                else
                    _cache.Remove(key); // expired
            }

            var response = await QueryDnsAsync(domain, isAAAA);
            if (response.addresses.Length > 0)
            {
                _cache[key] = new CacheEntry
                {
                    Addresses = response.addresses,
                    ExpireAt = DateTime.UtcNow.AddSeconds(response.ttl)
                };
            }
            return response.addresses;
        }

        private async Task<(IPAddress[] addresses, int ttl)> QueryDnsAsync(string domain, bool isAAAA)
        {
            var query = BuildDnsQuery(domain, isAAAA);
            var response = await SendDnsQueryAsync(query, _dnsServer.Address.ToString(), _dnsServer.Port);
            return ParseDnsResponse(response, isAAAA);
        }

        private static byte[] BuildDnsQuery(string domain, bool isAAAA)
        {
            Random rand = new Random();
            ushort id = (ushort)rand.Next(0, ushort.MaxValue);

            byte[] header = new byte[12];
            header[0] = (byte)(id >> 8);
            header[1] = (byte)(id & 0xFF);
            header[2] = 0x01; // recursion desired
            header[5] = 0x01; // QDCOUNT = 1

            var qname = new List<byte>();
            foreach (var part in domain.Split('.'))
            {
                qname.Add((byte)part.Length);
                qname.AddRange(Encoding.ASCII.GetBytes(part));
            }
            qname.Add(0); // end of domain

            ushort qtype = isAAAA ? (ushort)28 : (ushort)1;
            byte[] question = new byte[qname.Count + 4];
            qname.CopyTo(question);
            question[^4] = (byte)(qtype >> 8);
            question[^3] = (byte)(qtype & 0xFF);
            question[^2] = 0x00; // QCLASS = IN
            question[^1] = 0x01;

            return header.Concat(question).ToArray();
        }

        private static async Task<byte[]> SendDnsQueryAsync(byte[] query, string dnsServer, int port)
        {
            using var udp = new UdpClient();
            await udp.SendAsync(query, query.Length, dnsServer, port);
            var result = await udp.ReceiveAsync();
            return result.Buffer;
        }

        private static (IPAddress[] addresses, int ttl) ParseDnsResponse(byte[] response, bool isAAAA)
        {
            int answerCount = (response[6] << 8) | response[7];
            int offset = 12;

            // Skip QNAME
            while (response[offset] != 0)
                offset += response[offset] + 1;
            offset += 5; // null + QTYPE(2) + QCLASS(2)

            List<IPAddress> ips = new List<IPAddress>();
            int minTTL = int.MaxValue;

            for (int i = 0; i < answerCount; i++)
            {
                // Skip name
                if ((response[offset] & 0xC0) == 0xC0)
                    offset += 2;
                else
                    while (response[offset++] != 0) ;

                ushort type = (ushort)((response[offset] << 8) | response[offset + 1]);
                ushort clas = (ushort)((response[offset + 2] << 8) | response[offset + 3]);
                int ttl = (response[offset + 4] << 24) | (response[offset + 5] << 16) | (response[offset + 6] << 8) | response[offset + 7];
                offset += 8;
                ushort rdlength = (ushort)((response[offset] << 8) | response[offset + 1]);
                offset += 2;

                if (clas == 1 && ((isAAAA && type == 28) || (!isAAAA && type == 1)))
                {
                    minTTL = Math.Min(minTTL, ttl);

                    if (isAAAA && rdlength == 16)
                    {
                        ips.Add(new IPAddress(response.Skip(offset).Take(16).ToArray()));
                    }
                    else if (!isAAAA && rdlength == 4)
                    {
                        ips.Add(new IPAddress(response.Skip(offset).Take(4).ToArray()));
                    }
                }
                offset += rdlength;
            }

            if (minTTL == int.MaxValue) minTTL = 300; // fallback TTL 5 min
            return (ips.ToArray(), minTTL);
        }

        private class CacheEntry
        {
            public IPAddress[] Addresses { get; set; }
            public DateTime ExpireAt { get; set; }
        }
    }
}