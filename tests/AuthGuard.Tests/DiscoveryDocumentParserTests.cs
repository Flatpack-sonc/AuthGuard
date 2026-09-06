using AuthGuard.Core.Discovery;
using FluentAssertions;

namespace AuthGuard.Tests;

public class DiscoveryDocumentParserTests
{
    [Fact]
    public void ParseConfiguration_ReadsMajorFields()
    {
        var json = FixtureLoader.Read("good-discovery.json");
        var config = DiscoveryDocumentParser.ParseConfiguration(json);

        config.Issuer.Should().Be("https://good.example.com");
        config.AuthorizationEndpoint.Should().NotBeNullOrWhiteSpace();
        config.TokenEndpoint.Should().NotBeNullOrWhiteSpace();
        config.JwksUri.Should().NotBeNullOrWhiteSpace();
        config.CodeChallengeMethodsSupported.Should().Contain("S256");
        config.AuthorizationResponseIssParameterSupported.Should().BeTrue();
        config.RawJson.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void ParseJwks_ReadsKeys()
    {
        var jwks = DiscoveryDocumentParser.ParseJwks(FixtureLoader.Read("good-jwks.json"));
        jwks.Keys.Should().NotBeNull();
        jwks.Keys!.Should().HaveCount(2);
        jwks.Keys.Should().OnlyContain(k => !string.IsNullOrWhiteSpace(k.Kid));
    }

    [Theory]
    [InlineData("https://example.com", "https://example.com/.well-known/openid-configuration")]
    [InlineData("https://example.com/", "https://example.com/.well-known/openid-configuration")]
    [InlineData("example.com", "https://example.com/.well-known/openid-configuration")]
    [InlineData("https://example.com/.well-known/openid-configuration", "https://example.com/.well-known/openid-configuration")]
    public void BuildDiscoveryUrl_NormalizesIssuer(string input, string expected)
    {
        DiscoveryDocumentParser.BuildDiscoveryUrl(input).Should().Be(expected);
    }

    [Fact]
    public void NormalizeIssuerUrl_RejectsInvalid()
    {
        var act = () => DiscoveryDocumentParser.NormalizeIssuerUrl("not a url");
        act.Should().Throw<ArgumentException>();
    }
}
