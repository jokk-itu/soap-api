using System.Xml;

namespace Api.Common;

public class WSSecurityOperation
{
    public required string WsuId { get; init; }
    public required XmlElement Element { get; init; }
}