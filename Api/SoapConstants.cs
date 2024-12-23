namespace Api;

public static class SoapConstants
{
    public const string SoapPrefix = "soap";
    public const string SoapVersion1_1Namespace = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string SoapVersion1_2Namespace = "http://www.w3.org/2003/05/soap-envelope";
    public const string SoapEncodingPrefix = "enc";
    public const string SoapEncodingStyle = "http://schemas.xmlsoap.org/soap/encoding/";

    public const string ActorAttribute = "actor";
    public const string MustUnderstandAttribute = "mustUnderstand";
    public const string RoleAttribute = "role";

    public const string ActionHeader = "SOAPAction";

    public const string SigPrefix = "ds";
    public const string EncPrefix = "xenc";
    public const string Wss1_0Prefix = "wsse";
    public const string Wss1_1Prefix = "wsse11";
    public const string WsuPrefix = "wsu";

    public const string SigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    public const string EncNamespace = "http://www.w3.org/2001/04/xmlenc#";
    public const string Wss10Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public const string Wss11Namespace = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    public const string WsuNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    public const string CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public const string Base64EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    public const string CertificateValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

    /*
     * wsse:Security class (attributes: actor, role, mustUnderstand)
     * * wsse:UsernameToken (attributes: wsu:Id)
     * * * Username (required)
     *
     * * wsse:BinarySecurityToken (attributes: wsu:Id, ValueType, EncodingType)
     *
     * * wsse:SecurityTokenReference (attributes: wsu:Id, wsse11:TokenType, wsse:Usage)
     * * * wsse:Reference (attributes: URI, ValueType)
     * * * wsse:KeyIdentifier (attributes: wsu:Id, ValueType, EncodingType)
     * * * wsse:Embedded (attributes: wsu:Id)
     * * * * Generic argument
     * * * ds:KeyInfo
     * * * * wsse:KeyIdentifier
     *
     * * wsu:Timestamp (attributes: wsu:Id)
     * * * wsu:Created and wsu:Expires
     */
}
