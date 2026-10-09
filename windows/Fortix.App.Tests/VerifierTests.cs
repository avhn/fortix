using System.ComponentModel;
using Fortix.App.Model;
using Fortix.Core.Client;

namespace Fortix.App.Tests;

/// <summary>
/// Exercises every acceptance and rejection of pipe server verification with scripted system facts.
/// </summary>
public sealed class VerifierTests
{
    /// <summary>The trusted installation directory used by the fakes.</summary>
    private const string Directory = @"C:\Program Files\Fortix";

    /// <summary>The configured helper image used by the fakes.</summary>
    private const string Image = @"C:\Program Files\Fortix\fortix-helper.exe";

    /// <summary>
    /// Scripted operating system facts; every field can be changed per test.
    /// </summary>
    private sealed class FakeInspector : IServiceInspector, IHelperServiceQuery
    {
        /// <summary>Gets or sets the statuses returned in order; the last repeats.</summary>
        public List<ServiceProcessStatus> Statuses { get; set; } = [new(4242, 4, 0x10)];

        /// <summary>Gets or sets the stored configuration.</summary>
        public ServiceConfiguration Config { get; set; } = new("\"" + Image + "\"", 0x10, "LocalSystem");

        /// <summary>Gets or sets the inspected image.</summary>
        public string ProcessImage { get; set; } = Image;

        /// <summary>Gets or sets whether the token user is LocalSystem.</summary>
        public bool LocalSystem { get; set; } = true;

        /// <summary>Gets or sets the error process inspection raises, or zero.</summary>
        public int InspectError { get; set; }

        /// <summary>Gets or sets the kernel image name for the fallback.</summary>
        public string Kernel { get; set; } = @"\Device\HarddiskVolume3\Program Files\Fortix\fortix-helper.exe";

        /// <summary>Gets how many status queries ran.</summary>
        public int StatusQueries { get; private set; }

        /// <summary>Gets whether the service handle was released.</summary>
        public bool Disposed { get; private set; }

        /// <inheritdoc/>
        public IHelperServiceQuery OpenHelperService() => this;

        /// <inheritdoc/>
        public string InstallationDirectory() => Directory;

        /// <inheritdoc/>
        public InspectedProcess InspectProcess(uint processId) =>
            InspectError != 0 ? throw new Win32Exception(InspectError) : new InspectedProcess(ProcessImage, LocalSystem, null);

        /// <inheritdoc/>
        public string KernelImageName(uint processId) => Kernel;

        /// <inheritdoc/>
        public string DosDeviceTarget(string drive) => drive == "C:" ? @"\Device\HarddiskVolume3" : throw new Win32Exception(2);

        /// <inheritdoc/>
        public ServiceProcessStatus QueryStatus() => Statuses[Math.Min(StatusQueries++, Statuses.Count - 1)];

        /// <inheritdoc/>
        public ServiceConfiguration QueryConfig() => Config;

        /// <inheritdoc/>
        public void Dispose() => Disposed = true;
    }

    /// <summary>
    /// A transport without a pipe handle.
    /// </summary>
    private sealed class PlainTransport : IHelperTransport
    {
        /// <inheritdoc/>
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) => ValueTask.FromResult(0);

        /// <inheritdoc/>
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) => ValueTask.CompletedTask;

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    /// <summary>
    /// Runs verification against the scripted helper's pipe process 4242.
    /// </summary>
    /// <param name="inspector">The facts.</param>
    /// <returns>The rejection message, or null when accepted.</returns>
    private static string? Run(FakeInspector inspector)
    {
        try
        {
            new PipeServerVerifier(inspector).Verify(new ScriptedHelper(), CancellationToken.None);
            return null;
        }
        catch (HelperIdentityException e)
        {
            return e.Message;
        }
    }

    /// <summary>
    /// The installed, running, LocalSystem service is accepted and its handle released.
    /// </summary>
    [Fact]
    public void AcceptsInstalledService()
    {
        var inspector = new FakeInspector();
        Assert.Null(Run(inspector));
        Assert.Equal(2, inspector.StatusQueries);
        Assert.True(inspector.Disposed);
    }

    /// <summary>
    /// Each mismatched fact rejects with the command-line client's message.
    /// </summary>
    /// <param name="change">The fact to break.</param>
    /// <param name="expected">The rejection.</param>
    [Theory]
    [InlineData("pid", "pipe owner is not the running helper service")]
    [InlineData("stopped", "pipe owner is not the running helper service")]
    [InlineData("shared", "pipe owner is not the running helper service")]
    [InlineData("configType", "unexpected helper service identity")]
    [InlineData("user", "unexpected helper service identity")]
    [InlineData("image", "unexpected helper service image")]
    [InlineData("arguments", "unexpected helper service image")]
    [InlineData("outside", "helper image is outside the installation directory")]
    [InlineData("restarted", "helper service changed during verification")]
    [InlineData("deniedAccount", "unexpected helper service account")]
    [InlineData("deniedKernel", "unexpected helper service image")]
    public void RejectsMismatches(string change, string expected)
    {
        var inspector = new FakeInspector();
        switch (change)
        {
            case "pid": inspector.Statuses = [new(7, 4, 0x10)]; break;
            case "stopped": inspector.Statuses = [new(4242, 1, 0x10)]; break;
            case "shared": inspector.Statuses = [new(4242, 4, 0x20)]; break;
            case "configType": inspector.Config = inspector.Config with { ServiceType = 0x20 }; break;
            case "user": inspector.LocalSystem = false; break;
            case "image": inspector.ProcessImage = @"C:\Program Files\Fortix\other.exe"; break;
            case "arguments": inspector.Config = inspector.Config with { Binary = "\"" + Image + "\" --debug" }; break;
            case "outside":
                inspector.Config = inspector.Config with { Binary = @"C:\Users\Public\fortix-helper.exe" };
                inspector.ProcessImage = @"C:\Users\Public\fortix-helper.exe";
                break;
            case "restarted": inspector.Statuses = [new(4242, 4, 0x10), new(4243, 4, 0x10)]; break;
            case "deniedAccount":
                inspector.InspectError = 5;
                inspector.Config = inspector.Config with { Account = @".\someone" };
                break;
            case "deniedKernel":
                inspector.InspectError = 5;
                inspector.Kernel = @"\Device\HarddiskVolume3\Users\Public\fortix-helper.exe";
                break;
        }
        Assert.Equal(expected, Run(inspector));
    }

    /// <summary>
    /// A process that denies inspection is accepted when the account and kernel image confirm it.
    /// </summary>
    [Fact]
    public void AccessDeniedFallsBackToKernelImage()
    {
        var inspector = new FakeInspector { InspectError = 5, LocalSystem = false };
        Assert.Null(Run(inspector));
        Assert.Equal(2, inspector.StatusQueries);
    }

    /// <summary>
    /// Any inspection failure other than access denied stays a failure.
    /// </summary>
    [Fact]
    public void OtherInspectionErrorsAreNotFallback()
    {
        var inspector = new FakeInspector { InspectError = 87 };
        var error = Assert.Throws<Win32Exception>(() => new PipeServerVerifier(inspector).Verify(new ScriptedHelper(), CancellationToken.None));
        Assert.Equal(87, error.NativeErrorCode);
    }

    /// <summary>
    /// A transport without a pipe cannot be verified and is never trusted.
    /// </summary>
    [Fact]
    public void RejectsTransportWithoutPipe()
    {
        var error = Assert.Throws<HelperIdentityException>(() => new PipeServerVerifier(new FakeInspector()).Verify(new PlainTransport(), CancellationToken.None));
        Assert.Equal("transport has no verifiable pipe handle", error.Message);
    }

    /// <summary>
    /// A rejected server never receives a byte, because verification runs before the hello request.
    /// </summary>
    [Fact]
    public async Task RejectedServerReceivesNothing()
    {
        var helper = new ScriptedHelper();
        var inspector = new FakeInspector { Statuses = [new(7, 4, 0x10)] };
        await Assert.ThrowsAnyAsync<Exception>(() => HelperClient.ConnectAsync(helper, new PipeServerVerifier(inspector), new HelperClientOptions(), CancellationToken.None));
        Assert.Equal(0, helper.BytesWritten);
    }

    /// <summary>
    /// Kernel image matching maps the drive to its device and refuses other devices.
    /// </summary>
    [Fact]
    public void KernelImageMatching()
    {
        Assert.Equal(Image, ServiceIdentityRules.MatchKernelImage(@"\device\harddiskvolume3\program files\fortix\FORTIX-HELPER.EXE", @"\Device\HarddiskVolume3", "\"" + Image + "\""));
        Assert.Throws<HelperIdentityException>(() => ServiceIdentityRules.MatchKernelImage(@"\Device\HarddiskVolume4\Program Files\Fortix\fortix-helper.exe", @"\Device\HarddiskVolume3", Image));
        Assert.Throws<HelperIdentityException>(() => ServiceIdentityRules.MatchKernelImage(@"\??\C:\Program Files\Fortix\fortix-helper.exe", @"\??\C:", Image));
    }

    /// <summary>
    /// Only canonical local drive paths are valid.
    /// </summary>
    /// <param name="path">The candidate.</param>
    /// <param name="valid">The expected result.</param>
    [Theory]
    [InlineData(@"C:\Program Files\Fortix\fortix-helper.exe", true)]
    [InlineData(@"C:\", true)]
    [InlineData(@"c:\fortix\helper.exe", true)]
    [InlineData(@"\\server\share\fortix-helper.exe", false)]
    [InlineData(@"\\?\C:\Program Files\Fortix\fortix-helper.exe", false)]
    [InlineData(@"C:Program Files\fortix-helper.exe", false)]
    [InlineData(@"C:/Program Files/Fortix/fortix-helper.exe", false)]
    [InlineData(@"C:\Program Files\Fortix\fortix-helper.exe:stream", false)]
    [InlineData(@"C:\Program Files\Fortix\..\fortix-helper.exe", false)]
    [InlineData(@"C:\Program Files\Fortix\.\fortix-helper.exe", false)]
    [InlineData(@"C:\Program Files\Fortix\\fortix-helper.exe", false)]
    [InlineData(@"C:\Program Files\Fortix\fortix-helper.exe ", false)]
    [InlineData(@"C:\Program Files\Fortix\fortix-helper.exe.", false)]
    [InlineData(@"C:\Program Files\Fortix\NUL", false)]
    [InlineData(@"C:\Program Files\Fortix\com1.txt", false)]
    [InlineData(@"C:\Program Files\Fortix\a*b.exe", false)]
    [InlineData("C:\\Program Files\\Fortix\\a\u0001.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void PathValidation(string? path, bool valid) => Assert.Equal(valid, ServiceIdentityRules.ValidPath(path));

    /// <summary>
    /// A lone surrogate is rejected; it is built at run time because attribute data cannot carry one.
    /// </summary>
    [Fact]
    public void PathWithLoneSurrogateIsInvalid() =>
        Assert.False(ServiceIdentityRules.ValidPath(@"C:\Program Files\Fortix\" + (char)0xd800 + ".exe"));
}
