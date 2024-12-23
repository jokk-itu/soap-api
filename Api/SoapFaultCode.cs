using System.Xml.Serialization;

namespace Api;

public class SoapFaultCode
{
    [XmlElement(ElementName = "Value", IsNullable = false)]
    public required string Value { get; set; }

    [XmlElement(ElementName = "SubCode", IsNullable = true)]
    public SoapFaultCode? SubCode { get; set; }
}
