using AuthGuard.Core.Models;

namespace AuthGuard.Core.Policy;

public interface IPolicyRule
{
    string RuleId { get; }
    IEnumerable<Finding> Evaluate(AuditContext context);
}
