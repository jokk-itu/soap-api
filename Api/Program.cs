var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers().AddXmlSerializerFormatters();

var app = builder.Build();

app.MapControllers();

app.Run();