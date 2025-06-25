FROM mcr.microsoft.com/dotnet/sdk:9 AS build
WORKDIR /app

ARG BUILD_CONFIG=Release

COPY *.csproj ./
RUN dotnet restore

COPY . ./
RUN dotnet publish -c $BUILD_CONFIG -o /app/out

FROM mcr.microsoft.com/dotnet/runtime:9 AS runtime
WORKDIR /app

COPY --from=build /app/out ./

ENTRYPOINT ["dotnet", "CNET.dll"]
