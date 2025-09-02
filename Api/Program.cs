using Api;
using Api.Common;
using Api.Contracts;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddControllers()
    .AddXmlSerializerFormatters();

builder.Services
    .AddHttpClient("SoapApi", httpClient =>
    {
        httpClient.BaseAddress = new Uri("http://localhost:8088/");
    });

builder.Services.AddScoped<ISoapClient<CalculateAddRequest, CalculateAddResponse>>(services =>
{
    var privateCertificateBytes = File.ReadAllBytes("oces3_private.p12");
    var privateCertificate = new X509Certificate2(privateCertificateBytes, "c5,PnmF8;m4I");

    var publicCertificateBytes = File.ReadAllBytes("oces3_public.cer");
    var publicCertificate = new X509Certificate2(publicCertificateBytes);

    var soap11AttributeGenerator = new Soap11AttributeGenerator();

    var requestWsSecurityPolicies = new List<IRequestWsSecurityPolicy>
    {
        new TimestampWsSecurityPolicy(soap11AttributeGenerator),
        new BinaryTokenSigningWsSecurityPolicy(soap11AttributeGenerator, privateCertificate, publicCertificate)
    };

    var responseWsSecurityPolicies = new List<IResponseWsSecurityPolicy>
    {
        new TimestampWsSecurityPolicy(soap11AttributeGenerator),
        new BinaryTokenSigningWsSecurityPolicy(soap11AttributeGenerator, privateCertificate, publicCertificate)
    };

    return new CalculateAddSoapClient(
        services.GetRequiredService<IHttpClientFactory>(),
        requestWsSecurityPolicies,
        responseWsSecurityPolicies);
});

var app = builder.Build();

app.MapControllers();

app.Run();