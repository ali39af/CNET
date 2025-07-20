using System.ComponentModel.DataAnnotations;

namespace CNET
{
    public enum DomainType
    {
        NSFW = 0x00,
        Scam = 0x01,
        Ads = 0x02,
        Proxy = 0x03
    }

    public class Domain
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string Match { get; set; } = string.Empty;

        public DomainType Type { get; set; } = DomainType.NSFW;
    }

}