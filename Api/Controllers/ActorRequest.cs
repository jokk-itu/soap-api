using System.Xml.Serialization;

namespace Api.Controllers;

[XmlType(Namespace = "http://soap-api.com/actor")]
public sealed class ActorRequest
{
    [XmlElement(ElementName = "Name", IsNullable = false)]
    public required string Name { get; set; }
}