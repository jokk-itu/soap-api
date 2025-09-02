using System.Xml;
using System.Xml.Serialization;

namespace Api;

[XmlRoot(Namespace = SoapConstants.SoapVersion1_1Namespace, ElementName = "Fault")]
public class Soap11Fault
{
    [XmlElement(ElementName = "faultcode", IsNullable = false)]
    public required string FaultCode { get; set; }

    [XmlElement(ElementName = "faultstring", IsNullable = false)]
    public required string FaultString { get; set; }

    [XmlElement(ElementName = "faultactor", IsNullable = true)]
    public string? FaultActor { get; set; }

    [XmlElement(ElementName = "detail", IsNullable = true)]
    public XmlElement? Detail { get; set; }
}
