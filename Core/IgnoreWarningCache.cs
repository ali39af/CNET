using System.Collections.Concurrent;
using System.Net;

namespace CNET
{
    public class IgnoreWarningCache
    {
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<IPAddress, byte>> _cache =
            new(StringComparer.OrdinalIgnoreCase);

        public void Add(string domain, IPAddress ipAddress)
        {
            var ipSet = _cache.GetOrAdd(domain, _ => new ConcurrentDictionary<IPAddress, byte>());
            ipSet.TryAdd(ipAddress, 0);
        }

        public bool Contains(string domain, IPAddress ipAddress)
        {
            return _cache.TryGetValue(domain, out var ipSet) && ipSet.ContainsKey(ipAddress);
        }
    }
}
