FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["sharepasswordAzure/sharepasswordAzure.csproj", "sharepasswordAzure/"]
RUN dotnet restore "sharepasswordAzure/sharepasswordAzure.csproj"

COPY . .
WORKDIR "/src/sharepasswordAzure"
RUN dotnet publish "sharepasswordAzure.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "sharepasswordAzure.dll"]
