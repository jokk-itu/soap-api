using System.Xml.Serialization;

namespace Api.Contracts;

[XmlRoot(Namespace = "http://tempuri.org/", ElementName = "Add")]
public class CalculateAddRequest
{
    [XmlElement(ElementName = "intA", IsNullable = false)]
    public required int A { get; set; }

    [XmlElement(ElementName = "intB", IsNullable = false)]
    public required int B { get; set; }
}
