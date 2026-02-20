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
	AzureKeyVault__VaultUri= \
	AzureKeyVault__TenantId= \
	AzureKeyVault__ClientId= \
	AzureKeyVault__ClientSecret= \
	AzureKeyVault__SecretPrefix=sharepassword \
	AzureTableAudit__ServiceSasUrl= \
	AzureTableAudit__TableName=auditlogs \
	AzureTableAudit__PartitionKey=audit \
	AdminAuth__Username=admin \
	AdminAuth__Password= \
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
