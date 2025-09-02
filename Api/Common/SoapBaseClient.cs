using System.Security;
using System.Text;
using System.Xml.Serialization;
using System.Xml;

namespace Api.Common;

public abstract class SoapBaseClient<TRequest, TResponse> : ISoapClient<TRequest, TResponse>
{
    private const string SoapPrefix = "soap";
    private const string RequestPrefix = "request";
    private const string ResponsePrefix = "response";

    private readonly HttpClient _httpClient;
    private readonly IEnumerable<IRequestWsSecurityPolicy> _requestWsSecurityPolicies;
    private readonly IEnumerable<IResponseWsSecurityPolicy> _responseWsSecurityPolicies;
    private readonly ISoapFaultPolicy _soapFaultPolicy;

    protected SoapBaseClient(
        HttpClient httpClient,
        IEnumerable<IRequestWsSecurityPolicy> requestWsSecurityPolicies,
        IEnumerable<IResponseWsSecurityPolicy> responseWsSecurityPolicies,
        ISoapFaultPolicy soapFaultPolicy)
    {
        _httpClient = httpClient;
        _requestWsSecurityPolicies = requestWsSecurityPolicies;
        _responseWsSecurityPolicies = responseWsSecurityPolicies;
        _soapFaultPolicy = soapFaultPolicy;
    }

    protected abstract string RequestNamespace { get; }
    protected abstract string EndpointPath { get; }
    protected abstract string ContentType { get; }
    protected abstract string SoapNamespace { get; }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="soapHeader"></param>
    /// <returns></returns>
    protected virtual IEnumerable<WSSecurityOperation> AddSoapHeaderElements(XmlElement soapHeader)
    {
        return [];
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="soapBody"></param>
    /// <returns></returns>
    protected virtual IEnumerable<WSSecurityOperation> AddSoapBodyElements(XmlElement soapBody)
    {
        return [];
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="httpRequestMessage"></param>
    protected abstract void OnRequest(HttpRequestMessage httpRequestMessage);

    /// <inheritdoc/>
    public async Task<TResponse> Post(TRequest request, CancellationToken cancellationToken)
    {
        var requestXml = BuildSoapEnvelope(request);
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, EndpointPath)
        {
            Content = new StringContent(requestXml, Encoding.UTF8, ContentType)
        };

        OnRequest(httpRequestMessage);

        var httpResponseMessage = await _httpClient.SendAsync(httpRequestMessage, cancellationToken);
        httpResponseMessage.EnsureSuccessStatusCode();

        var responseContent = await httpResponseMessage.Content.ReadAsStreamAsync(cancellationToken);
        using var bodyReader = new StreamReader(responseContent);
        var xmlBody = await bodyReader.ReadToEndAsync(cancellationToken);

        var xmlDocument = new XmlDocument
        {
            // Whitespaces must be preserved, to make sure signatures are kept valid
            PreserveWhitespace = true
        };
        xmlDocument.LoadXml(xmlBody);

        var namespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
        namespaceManager.AddNamespace(SoapPrefix, SoapNamespace);
        namespaceManager.AddNamespace(ResponsePrefix, RequestNamespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_0Prefix, SoapConstants.Wss1_0Namespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_1Prefix, SoapConstants.Wss1_1Namespace);
        namespaceManager.AddNamespace(SoapConstants.WsuPrefix, SoapConstants.WsuNamespace);
        namespaceManager.AddNamespace(SoapConstants.SigPrefix, SoapConstants.SigNamespace);
        namespaceManager.AddNamespace(SoapConstants.EncPrefix, SoapConstants.EncNamespace);

        if (xmlDocument.SelectSingleNode("soap:Envelope", namespaceManager) is not XmlElement envelope)
        {
            throw new UnknownSoapEnvelopeException(xmlDocument);
        }

        _soapFaultPolicy.Apply(envelope);

        foreach (var responseWsSecurityPolicy in _responseWsSecurityPolicies)
        {
            var operationResult = responseWsSecurityPolicy.Apply(envelope);
            if (!operationResult.IsValid)
            {
                throw new SecurityException();
            }
        }

        var body = xmlDocument.SelectSingleNode("soap:Envelope/soap:Body", namespaceManager)!;

        var xmlSerializer = new XmlSerializer(typeof(TResponse));
        using var stringReader = new StringReader(body.InnerXml);
        var response = (TResponse)xmlSerializer.Deserialize(stringReader)!;

        return response;
    }

    private string BuildSoapEnvelope(TRequest request)
    {
        var xmlDocument = new XmlDocument();
        var envelope = xmlDocument.CreateElement(SoapPrefix, "Envelope", SoapNamespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.Wss1_0Prefix}", SoapConstants.Wss1_0Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.Wss1_1Prefix}", SoapConstants.Wss1_1Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.WsuPrefix}", SoapConstants.WsuNamespace);
        envelope.SetAttribute($"xmlns:{RequestPrefix}", RequestNamespace);
        xmlDocument.AppendChild(envelope);

        var header = xmlDocument.CreateElement(SoapPrefix, "Header", SoapNamespace);
        envelope.AppendChild(header);

        var headerSoapOperationResult = AddSoapHeaderElements(header);

        var bodyId = Guid.NewGuid().ToString();
        var body = xmlDocument.CreateElement(SoapPrefix, "Body", SoapNamespace);
        body.SetAttribute("Id", SoapConstants.WsuNamespace, bodyId);

        // the body must be appended to the envelope before navigation can occur
        envelope.AppendChild(body);

        using (var xmlWriter = body.CreateNavigator()!.AppendChild())
        {
            // write an empty whitespace to force omit the Xml declaration
            xmlWriter.WriteWhitespace("");

            var xmlSerializer = new XmlSerializer(typeof(TRequest), defaultNamespace: RequestNamespace);
            xmlSerializer.Serialize(xmlWriter, request);
        }

        var bodyWsSecurityOperations = AddSoapBodyElements(body).ToList();
        bodyWsSecurityOperations.AddRange(headerSoapOperationResult);
        bodyWsSecurityOperations.Add(new WSSecurityOperation
        {
            WsuId = bodyId,
            Element = body,
            SignElement = true,
            EncryptElement = true
        });

        foreach (var postRequestWsSecurityPolicy in _requestWsSecurityPolicies)
        {
            postRequestWsSecurityPolicy.Apply(header, bodyWsSecurityOperations);
        }

        return xmlDocument.InnerXml;
    }
}