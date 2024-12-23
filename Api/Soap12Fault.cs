using System.Xml.Serialization;

namespace Api;

[XmlType(Namespace = SoapConstants.SoapVersion1_2Namespace, TypeName = "Fault")]
public class Soap12Fault<TDetail>
{
    [XmlElement(ElementName = "Code", IsNullable = false)]
    public required SoapFaultCode Code { get; set; }

    [XmlElement(ElementName = "Reason", IsNullable = false)]
    public required SoapFaultReason Reason { get; set; }

    [XmlElement(ElementName = "Node", IsNullable = true)]
    public string? Node { get; set; }

    [XmlElement(ElementName = "Role", IsNullable = true)]
    public string? Role { get; set; }

    [XmlElement(ElementName = "Detail", IsNullable = true)]
    public TDetail? Detail { get; set; }
}
