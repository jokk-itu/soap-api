using System.Xml;

namespace Api.Common;

public class WSSecurityOperation
{
    public required string WsuId { get; init; }
    public required XmlElement Element { get; init; }
    public bool EncryptElement { get; init; }
    public bool SignElement { get; init; }
}