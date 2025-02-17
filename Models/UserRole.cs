using System.ComponentModel.DataAnnotations;

namespace FansVoice.Auth.Models;

public class UserRole
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid UserId { get; set; }

    [Required]
    public Guid RoleId { get; set; }

    public User User { get; set; }
    public Role Role { get; set; }
}