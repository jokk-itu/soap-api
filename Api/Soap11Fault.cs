using System.Xml.Serialization;

namespace Api;

[XmlType(Namespace = SoapConstants.SoapVersion1_1Namespace, TypeName = "Fault")]
public class Soap11Fault<TDetail>
{
    [XmlElement(ElementName = "faultcode", IsNullable = false)]
    public required string FaultCode { get; set; }

    [XmlElement(ElementName = "faultstring", IsNullable = false)]
    public required string FaultString { get; set; }

    [XmlElement(ElementName = "faultactor", IsNullable = true)]
    public string? FaultActor { get; set; }

    [XmlElement(ElementName = "detail", IsNullable = true)]
    public TDetail? Detail { get; set; }
}
