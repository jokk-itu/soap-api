namespace Api.Common;

public abstract class Soap11Client<TRequest, TResponse> : SoapBaseClient<TRequest, TResponse>
{
    protected Soap11Client(
        HttpClient httpClient,
        IEnumerable<IRequestWsSecurityPolicy> requestWsSecurityPolicies,
        IEnumerable<IResponseWsSecurityPolicy> responseWsSecurityPolicies,
        ISoapFaultPolicy soapFaultPolicy)
        : base(httpClient, requestWsSecurityPolicies, responseWsSecurityPolicies, soapFaultPolicy)
    {
    }

    protected abstract string SoapActionUri { get; }

    protected override string ContentType => "text/xml";

    protected override string SoapNamespace => "http://schemas.xmlsoap.org/soap/envelope/";

    protected override void OnRequest(HttpRequestMessage httpRequestMessage)
    {
        httpRequestMessage.Headers.Add("SOAPAction", SoapActionUri);
    }
}
