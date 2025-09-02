using System.Xml;
using System.Xml.Serialization;

namespace Api.Common;

public class Soap11Exception : Exception
{
    public string FaultCode { get; private init; }
    public string FaultString { get; private init; }
    public string? FaultActor { get; }
    public XmlElement? Detail { get; }

    public Soap11Exception(Soap11Fault fault)
    {
        FaultCode = fault.FaultCode;
        FaultString = fault.FaultString;
        FaultActor = fault.FaultActor;
        Detail = fault.Detail;
    }

    public TDetail? DeserializeDetail<TDetail>() where TDetail : class
    {
        if (Detail is null)
        {
            return null;
        }

        var xmlSerializer = new XmlSerializer(typeof(TDetail));
        using var stringReader = new StringReader(Detail.InnerXml);
        return (TDetail?)xmlSerializer.Deserialize(stringReader);
    }
}
