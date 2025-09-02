using System.Xml.Serialization;

namespace Api.Contracts;

public class SoapFaultReason
{
    [XmlElement(ElementName = "Text", IsNullable = false)]
    public required string Text { get; set; }
}
