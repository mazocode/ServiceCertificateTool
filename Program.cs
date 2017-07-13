using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace ServiceCertificateTool
{
	class Program
	{
		public const string CRYPTOGRAPHY_PROVIDER_NAME = "Microsoft Enhanced RSA and AES Cryptographic Provider";
		public const int CERTIFICATE_KEYSIZE_BITS = 4096;
		public const string CERTIFICATE_TEMPLATE_NAME = "WebServer";

		private const int CC_DEFAULTCONFIG = 0;
		private const int CC_UIPICKCONFIG = 0x1;
		private const int CR_IN_BASE64 = 0x1;
		private const int CR_IN_FORMATANY = 0;
		private const int CR_IN_PKCS10 = 0x100;
		private const int CR_DISP_ISSUED = 0x3;
		private const int CR_DISP_UNDER_SUBMISSION = 0x5;
		private const int CR_OUT_BASE64 = 0x1;
		private const int CR_OUT_CHAIN = 0x100;

		/// <summary>
		/// See http://technet.microsoft.com/de-de/library/ff182332(v=ws.10).aspx for development info
		/// </summary>
		static void Main(string[] args)
		{
			Console.WriteLine("This tool requests a certificate suitable for token signing from an active directory CA.");
			Console.WriteLine();

			WindowsIdentity id = WindowsIdentity.GetCurrent();
			WindowsPrincipal principal = new WindowsPrincipal(id);
			if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
			{
				Console.WriteLine("The operation requires Administrator rights on the local machine to termporarely access the certificate store.");
				Console.WriteLine("Continue with elevated permissions [y/N]?");
				if (!string.Equals("y", Console.ReadLine(), StringComparison.OrdinalIgnoreCase))
					return;

				// Launch myself with request for elevated permissions
				ProcessStartInfo proc = new ProcessStartInfo();
				proc.UseShellExecute = true;
				proc.WorkingDirectory = Environment.CurrentDirectory;
				proc.FileName = System.Reflection.Assembly.GetExecutingAssembly().Location;
				proc.Verb = "runas";

				try
				{
					var process = Process.Start(proc);
					Console.Write("Waiting for elevated process to end... ");
					process.WaitForExit();
					Console.Write("OK");
					return;
				}
				catch
				{
					// The user refused the elevation. 
					// Do nothing and return directly ... 
				}
				return;
			}

			Console.Write("Enter certificate Common Name or press ENTER to exit: ");
			var cn = Console.ReadLine();
			if (string.IsNullOrWhiteSpace(cn))
				return;

			Console.Write("Creating a certificate signing request... ");
			var objCSPs = new CERTENROLLLib.CCspInformationsClass();

			// Add all available CSPs
			objCSPs.AddAvailableCsps();

			var requestId = Guid.NewGuid().ToString("D");

			var privateKey = CreatePrivateKey(objCSPs, requestId);

			var objPkcs10 = new CERTENROLLLib.CX509CertificateRequestPkcs10Class();

			objPkcs10.InitializeFromPrivateKey(
				CERTENROLLLib.X509CertificateEnrollmentContext.ContextMachine,
				privateKey,
				""
			);

			var extensionKeyUsage = CreateExtensionKeyUsage();

			objPkcs10.X509Extensions.Add((CERTENROLLLib.CX509Extension)extensionKeyUsage);

			var enhancedKeyUsage = CreateExtensionEnhancedKeyUsage();

			objPkcs10.X509Extensions.Add((CERTENROLLLib.CX509Extension)enhancedKeyUsage);

			var smimeExt = CreateSMIMECapabilities(privateKey.CspStatus.CspInformation);

			objPkcs10.X509Extensions.Add((CERTENROLLLib.CX509Extension)smimeExt);

			var template = new CERTENROLLLib.CX509ExtensionTemplateName();

			template.InitializeEncode(CERTIFICATE_TEMPLATE_NAME);
			objPkcs10.X509Extensions.Add((CERTENROLLLib.CX509Extension)template);

			var subjectDN = new CERTENROLLLib.CX500DistinguishedNameClass();

			subjectDN.Encode(
				"CN=" + cn,
				CERTENROLLLib.X500NameFlags.XCN_CERT_NAME_STR_NONE
			);

			objPkcs10.Subject = subjectDN;
			objPkcs10.SmimeCapabilities = true;

			var enroll = new CERTENROLLLib.CX509EnrollmentClass();

			// Create enrollment request
			enroll.InitializeFromRequest(objPkcs10);
			enroll.CertificateFriendlyName = requestId;

			var csr = enroll.CreateRequest(CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64);

			Console.WriteLine("OK");

			Console.Write("Submitting certificate signing request... ");

			// Display dialog to select CA from
			var certConfig = new CERTCLILib.CCertConfigClass();
			var caConfig = certConfig.GetConfig(CC_UIPICKCONFIG);

			// Submit the request
			var certRequest = new CERTCLILib.CCertRequestClass();
			var disposition = certRequest.Submit(CR_IN_BASE64 | CR_IN_FORMATANY,
				csr,
				null,
				caConfig
			);

			if (CR_DISP_ISSUED != disposition) // Not enrolled
			{
				if (CR_DISP_UNDER_SUBMISSION == disposition) // Pending
				{
					throw new ApplicationException(string.Format("The certificate request is pending on CA {0}: {1}",
						caConfig, certRequest.GetDispositionMessage()));
				}

				throw new ApplicationException(string.Format("The certificate request failed on CA {0}: {1}" + Environment.NewLine + "{2}",
					caConfig, certRequest.GetDispositionMessage(), certRequest.GetLastStatus().ToString()));
			}

			// Get the certificate
			var base64RawCert = certRequest.GetCertificate(CR_OUT_BASE64); //  | CR_OUT_CHAIN

			Console.WriteLine("OK");

			// The only way I found to get the certificate is
			// - Install to certificate store
			// - Read and export from store
			// - Delete from store

			var response = new CERTENROLLLib.CX509EnrollmentClass(); 
 			response.Initialize(CERTENROLLLib.X509CertificateEnrollmentContext.ContextMachine);

 			response.InstallResponse( 
				CERTENROLLLib.InstallResponseRestrictionFlags.AllowUntrustedRoot, 
				base64RawCert, CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64, 
				null 
			);

			var pfx = response.CreatePFX((string)null, 
				CERTENROLLLib.PFXExportOptions.PFXExportEEOnly, 
				CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64);

			// Delete from local machines certificate store
			var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			try
			{
				store.Open(OpenFlags.ReadWrite);

				var certificate = (from X509Certificate2 cert in store.Certificates
								where cert.FriendlyName == requestId
								select cert).Single();

				var export = Convert.ToBase64String(certificate.Export(X509ContentType.Pkcs12)); ;
				using (var outfile = File.Open(cn + ".crt", FileMode.Create, FileAccess.Write, FileShare.None))
				{
					var buffer = Encoding.UTF8.GetBytes(export);
					outfile.Write(buffer, 0, buffer.Length);
					outfile.Flush();
				}

				store.Remove(certificate);
			}
			finally
			{
				store.Close();
			}

			using (var outfile = File.Open(cn + ".pfx", FileMode.Create, FileAccess.Write, FileShare.None))
			{
				var buffer = Convert.FromBase64String(pfx);
				outfile.Write(buffer, 0, buffer.Length);
				outfile.Flush();
			}

			Console.WriteLine("done, wrote file " + cn + ".pfx");

		}

		private static CERTENROLLLib.CX509ExtensionSmimeCapabilities CreateSMIMECapabilities(CERTENROLLLib.CCspInformation csp)
		{
			var smimeExt = new CERTENROLLLib.CX509ExtensionSmimeCapabilitiesClass();
			var smimes = new CERTENROLLLib.CSmimeCapabilitiesClass();
			smimes.AddFromCsp(csp);

			smimeExt.InitializeEncode(smimes);
			return smimeExt;
		}

		private static CERTENROLLLib.CX509ExtensionEnhancedKeyUsage CreateExtensionEnhancedKeyUsage()
		{
			var objectIds = new CERTENROLLLib.CObjectIdsClass();
			var objectId = new CERTENROLLLib.CObjectIdClass();
			var extensionEnhancedKeyUsage = new CERTENROLLLib.CX509ExtensionEnhancedKeyUsageClass();

			var clientObjectId = new CERTENROLLLib.CObjectIdClass();
			clientObjectId.InitializeFromValue("1.3.6.1.5.5.7.3.2");
			objectIds.Add(clientObjectId);
			var serverObjectId = new CERTENROLLLib.CObjectIdClass();
			serverObjectId.InitializeFromValue("1.3.6.1.5.5.7.3.1");
			objectIds.Add(serverObjectId);

			extensionEnhancedKeyUsage.InitializeEncode(objectIds);

			return extensionEnhancedKeyUsage;
		}

		private static CERTENROLLLib.CX509ExtensionKeyUsage CreateExtensionKeyUsage()
		{
			var extensionKeyUsage = new CERTENROLLLib.CX509ExtensionKeyUsageClass();

			// Key Usage Extension 
			extensionKeyUsage.InitializeEncode(
				CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
				CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
				CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
				CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE
			);

			return extensionKeyUsage;
		}

		static private CERTENROLLLib.CX509PrivateKey CreatePrivateKey(CERTENROLLLib.CCspInformations csps, string requestId)
		{
			var privateKey = new CERTENROLLLib.CX509PrivateKeyClass();

			//  Provide key container name, key length and key spec to the private key object
			privateKey.ContainerName = requestId;
			privateKey.ProviderName = CRYPTOGRAPHY_PROVIDER_NAME;
			privateKey.ProviderType = CERTENROLLLib.X509ProviderType.XCN_PROV_RSA_FULL;
			privateKey.Length = CERTIFICATE_KEYSIZE_BITS;
			privateKey.KeySpec = CERTENROLLLib.X509KeySpec.XCN_AT_KEYEXCHANGE;
			privateKey.KeyUsage = CERTENROLLLib.X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
			privateKey.KeyProtection = CERTENROLLLib.X509PrivateKeyProtection.XCN_NCRYPT_UI_NO_PROTECTION_FLAG;
			privateKey.MachineContext = true;
			privateKey.CspInformations = csps;
			privateKey.ExportPolicy = CERTENROLLLib.X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
				CERTENROLLLib.X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;

			//  Create the actual key pair
			privateKey.Create();

			return privateKey;
		}
	}
}
