FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["sharepasswordAzure/sharepasswordAzure.csproj", "sharepasswordAzure/"]
RUN dotnet restore "sharepasswordAzure/sharepasswordAzure.csproj"

COPY . .
WORKDIR "/src/sharepasswordAzure"
RUN dotnet publish "sharepasswordAzure.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080 \
	ASPNETCORE_ENVIRONMENT=Production \
	Application__EnableHttpsRedirection=false \
	Kestrel__Endpoints__Http__Url=http://+:8080 \
	Storage__Backend=sqlite \
	SqliteStorage__ConnectionString=Data Source=/app/data/sharepassword.db \
	SqliteStorage__ApplyMigrationsOnStartup=true \
	SqlServerStorage__ConnectionString= \
	SqlServerStorage__ApplyMigrationsOnStartup=true \
	PostgresqlStorage__ConnectionString= \
	PostgresqlStorage__ApplyMigrationsOnStartup=true \
	AzureStorage__KeyVault__VaultUri= \
	AzureStorage__KeyVault__TenantId= \
	AzureStorage__KeyVault__ClientId= \
	AzureStorage__KeyVault__ClientSecret= \
	AzureStorage__KeyVault__SecretPrefix=sharepassword \
	AzureStorage__TableAudit__ServiceSasUrl= \
	AzureStorage__TableAudit__TableName=auditlogs \
	AzureStorage__TableAudit__PartitionKey=audit \
	AdminAuth__Username=admin \
	AdminAuth__PasswordHash= \
	OidcAuth__Enabled=false \
	OidcAuth__Authority= \
	OidcAuth__ClientId= \
	OidcAuth__ClientSecret= \
	OidcAuth__CallbackPath=/signin-oidc \
	OidcAuth__SignedOutCallbackPath=/signout-callback-oidc \
	OidcAuth__RequireHttpsMetadata=true \
	OidcAuth__Scopes__0=openid \
	OidcAuth__Scopes__1=profile \
	OidcAuth__Scopes__2=email \
	Encryption__Passphrase= \
	Share__DefaultExpiryHours=4 \
	Share__CleanupIntervalSeconds=60 \
	Logging__LogLevel__Default=Information \
	Logging__LogLevel__Microsoft__AspNetCore=Warning \
	AllowedHosts=*
EXPOSE 8080

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "sharepasswordAzure.dll"]
