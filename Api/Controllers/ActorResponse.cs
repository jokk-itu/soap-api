using System.Xml.Serialization;

namespace Api.Controllers;

[XmlType(Namespace = "http://soap-api.com/actor")]
public class ActorResponse
{
    [XmlElement(ElementName = "Id", IsNullable = false)]
    public int Id { get; set; }
}
