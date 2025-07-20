using System.ComponentModel.DataAnnotations;

namespace CNET
{
    public class HotspotUser
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [StringLength(128)]
        public string Password { get; set; } = string.Empty;

        public long DataInBytes { get; set; } = 0;
        public long DataOutBytes { get; set; } = 0;
    }
}
