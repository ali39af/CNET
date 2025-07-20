// TODO Auto Remove base on TTL after while time pass

using System.Collections.Concurrent;
using System.Net;

namespace CNET
{
    public sealed class CacheDatabase
    {
        private static readonly Lazy<CacheDatabase> _instance = new(() => new CacheDatabase());
        public static CacheDatabase Instance => _instance.Value;

        private readonly TimeSpan IgnoreCacheTTL = TimeSpan.FromHours(2);
        private readonly TimeSpan LoginCacheTTL = TimeSpan.FromHours(6);
        private readonly TimeSpan RecentCacheTTL = TimeSpan.FromSeconds(60);

        private readonly ConcurrentDictionary<string, ConcurrentDictionary<IPAddress, DateTime>> _ignoreCache =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, (ConcurrentDictionary<IPAddress, byte> IPs, DateTime Expiry)> _loginCache =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, (DomainType Type, DateTime Expiry)> _recentCache =
            new(StringComparer.OrdinalIgnoreCase);

        private CacheDatabase() { }

        #region Ignore Cache

        public void AddIgnore(string domain, IPAddress ipAddress)
        {
            var ipSet = _ignoreCache.GetOrAdd(domain, _ => new ConcurrentDictionary<IPAddress, DateTime>());
            ipSet[ipAddress] = DateTime.UtcNow.Add(IgnoreCacheTTL);
        }

        public bool ContainsIgnore(string domain, IPAddress ipAddress)
        {
            if (_ignoreCache.TryGetValue(domain, out var ipSet) &&
                ipSet.TryGetValue(ipAddress, out var expiry))
            {
                if (expiry > DateTime.UtcNow)
                    return true;
                ipSet.TryRemove(ipAddress, out _);
            }
            return false;
        }

        #endregion

        #region Login Cache

        public void SetLogin(string username, IPAddress ipAddress)
        {
            var ipSet = new ConcurrentDictionary<IPAddress, byte>();
            ipSet[ipAddress] = 0;
            _loginCache[username] = (ipSet, DateTime.UtcNow.Add(LoginCacheTTL));
        }

        public bool ContainsLogin(IPAddress ipAddress)
        {
            foreach (var kvp in _loginCache)
            {
                var (ips, expiry) = kvp.Value;
                if (expiry > DateTime.UtcNow && ips.ContainsKey(ipAddress))
                    return true;
            }
            return false;
        }

        public bool ContainsLogin(string username)
        {
            if (_loginCache.TryGetValue(username, out var entry))
            {
                if (entry.Expiry > DateTime.UtcNow)
                    return true;

                _loginCache.TryRemove(username, out _);
            }
            return false;
        }

        public void RemoveLogin(string username)
        {
            _loginCache.TryRemove(username, out _);
        }

        #endregion

        #region Recent Cache

        public void SetRecent(string domain, DomainType type)
        {
            _recentCache[domain] = (type, DateTime.UtcNow.Add(RecentCacheTTL));
        }

        public bool TryGetRecent(string domain, out DomainType type)
        {
            if (_recentCache.TryGetValue(domain, out var entry))
            {
                if (entry.Expiry > DateTime.UtcNow)
                {
                    type = entry.Type;
                    return true;
                }
                _recentCache.TryRemove(domain, out _);
            }
            type = default;
            return false;
        }
        #endregion
    }
}
