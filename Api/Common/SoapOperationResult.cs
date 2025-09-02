namespace Api.Common;

public sealed class SoapOperationResult
{
    public bool IsValid { get; init; }
    public string? Reason { get; init; }
    public Exception? Exception { get; init; }
}