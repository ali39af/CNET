using System.Net;

namespace CNET
{
    public static class CidrMatcher
    {
        public static bool IsIpInCidrList(List<string> cidrList, string ipToCheck)
        {
            var ip = IPAddress.Parse(ipToCheck);
            foreach (var cidr in cidrList)
            {
                if (IsInCidrRange(ip, cidr))
                    return true;
            }
            return false;
        }

        private static bool IsInCidrRange(IPAddress ip, string cidr)
        {
            var parts = cidr.Split('/');
            var baseIp = IPAddress.Parse(parts[0]);
            var prefixLength = int.Parse(parts[1]);

            var ipBytes = ip.GetAddressBytes();
            var baseIpBytes = baseIp.GetAddressBytes();

            if (ipBytes.Length != baseIpBytes.Length)
                return false;

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != baseIpBytes[i])
                    return false;
            }

            if (remainingBits > 0)
            {
                int mask = 0xFF << (8 - remainingBits);
                if ((ipBytes[fullBytes] & mask) != (baseIpBytes[fullBytes] & mask))
                    return false;
            }

            return true;
        }
    }
}