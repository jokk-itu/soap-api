using System.Xml;

namespace Api.Common;

public class UnknownSoapEnvelopeException : Exception
{
    public XmlNode UnknownEnvelope { get; }

    public UnknownSoapEnvelopeException(XmlNode unknownEnvelope)
    {
        UnknownEnvelope = unknownEnvelope;
    }
}
