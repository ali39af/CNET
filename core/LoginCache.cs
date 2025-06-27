using System.Collections.Concurrent;
using System.Net;

namespace CNET
{
    public class LoginCache
    {
        private readonly ConcurrentDictionary<IPAddress, byte> _cache = new();

        public void Add(IPAddress ipAddress)
        {
            _cache.TryAdd(ipAddress, 0);
        }

        public bool Contains(IPAddress ipAddress)
        {
            return _cache.ContainsKey(ipAddress);
        }
    }
}
