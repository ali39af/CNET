namespace CNET
{
    public enum BlacklistType
    {
        NSFW,
        ADS,
        SCAM
    }

    public class Blacklist
    {
        private readonly HashSet<string> _nsfwDomains;
        private readonly HashSet<string> _adsDomains;
        private readonly HashSet<string> _scamDomains;

        public Blacklist(HashSet<string> nsfwDomains, HashSet<string> adsDomains, HashSet<string> scamDomains)
        {
            _nsfwDomains = nsfwDomains;
            _adsDomains = adsDomains;
            _scamDomains = scamDomains;
        }

        public (bool, BlacklistType) Exist(string domain)
        {
            if (_nsfwDomains.Contains(domain))
                return (true, BlacklistType.NSFW);
            if (_adsDomains.Contains(domain))
                return (true, BlacklistType.ADS);
            if (_scamDomains.Contains(domain))
                return (true, BlacklistType.SCAM);

            return (false, default);
        }
    }
}
