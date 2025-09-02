using System.Xml;

namespace Api.Common;

public class UnknownSoapFaultException : Exception
{
    public XmlNode UnknownFault { get; }

    public UnknownSoapFaultException(XmlNode unknownFault)
    {
        UnknownFault = unknownFault;
    }
}
