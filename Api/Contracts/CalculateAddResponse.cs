using System.Xml.Serialization;

namespace Api.Contracts;

[XmlRoot(Namespace = "http://tempuri.org/", ElementName = "AddResponse")]
public class CalculateAddResponse
{
    [XmlElement(ElementName = "AddResult", IsNullable = false)]
    public required int Result { get; set; }
}