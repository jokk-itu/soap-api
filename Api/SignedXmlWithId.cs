using System.Security.Cryptography.Xml;
using System.Xml;

namespace Api;

public class SignedXmlWithId : SignedXml
{
    public SignedXmlWithId(XmlDocument xml) : base(xml)
    {
    }

    public override XmlElement? GetIdElement(XmlDocument? doc, string id)
    {
        if (doc is null)
        {
            return null;
        }

        // check to see if it's a standard ID reference
        var idElem = base.GetIdElement(doc, id);

        // if it is not a standard id, then check wsu:Id
        if (idElem is null)
        {
            var nsManager = new XmlNamespaceManager(doc.NameTable);
            nsManager.AddNamespace(SoapConstants.WsuPrefix, SoapConstants.WsuNamespace);

            idElem = doc.SelectSingleNode("//*[@wsu:Id=\"" + id + "\"]", nsManager) as XmlElement;
        }

        return idElem;
    }
}