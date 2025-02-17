using System.ComponentModel.DataAnnotations;

namespace FansVoice.Auth.Models;

public class Role
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    [MaxLength(50)]
    public string Name { get; set; }

    [MaxLength(200)]
    public string? Description { get; set; }

    public List<UserRole> UserRoles { get; set; } = new();
}