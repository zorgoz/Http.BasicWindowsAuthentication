/*
 * Copyright 2018 Zoltan Zorgo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace TaltosWorks.Owin
{
	internal class BasicWindowsAuthenticationHandler : AuthenticationHandler<BasicWindowsAuthenticationOptions>
	{
		private readonly BasicWindowsAuthenticationOptions options;
		private readonly string challenge;

		public BasicWindowsAuthenticationHandler(BasicWindowsAuthenticationOptions options)
		{
			this.options = options;
			challenge = "Basic realm=" + options.Realm;
		}

		protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			var authValue = Request.Headers.Get("Authorization");
			if (string.IsNullOrEmpty(authValue) || !authValue.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
			{
				return null;
			}

			var token = authValue.Substring("Basic ".Length).Trim();
			var credentials = TryGetCredentialsFromBasicAuthHeader(token);

			if (!credentials.HasValue)
			{
				return null;
			}

			IntPtr userToken = IntPtr.Zero;
			if (Win32NativeMethods.LogonUser(credentials.Value.name
				, credentials.Value.domain ?? options.DefaultDomain
				, credentials.Value.password
				, (int)LogonType.LOGON32_LOGON_NETWORK_CLEARTEXT
				, (int)LogonProvider.LOGON32_PROVIDER_DEFAULT
				, ref userToken) == 0) // Authentication not succeeded
			{
				if (!options.FailSilently)
				{
					var error = Marshal.GetLastWin32Error();
					Context.Response.Headers.Append("X-LogonFailureReason", error == 0 ? "Unknown reason, check account!" : (new Win32Exception(error)).Message);
					Context.Response.Headers.Append("X-LogonFailureCode", error.ToString());
				}
				return null;
			}

			var identity = new WindowsIdentity(userToken);
			Win32NativeMethods.CloseHandle(userToken);

			return Task.FromResult(new AuthenticationTicket(identity, new AuthenticationProperties()));
		}

		protected override Task ApplyResponseChallengeAsync()
		{
			if (Response.StatusCode == 401)
			{
				var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
				if (challenge != null)
				{
					Response.Headers.AppendValues("WWW-Authenticate", this.challenge);
				}
			}

			return Task.FromResult<object>(null);
		}

		private static (string domain, string name, string password)? TryGetCredentialsFromBasicAuthHeader(string credentials)
		{
			string pair;
			try
			{
				pair = Encoding.UTF8.GetString(Convert.FromBase64String(credentials));
			}
			catch (FormatException)
			{
				return null;
			}
			catch (ArgumentException)
			{
				return null;
			}

			var username_password = pair.Split(':');
			if (username_password.Length != 2)
			{
				return null;
			}

			var username_domain = username_password[0].Split('\\');

			if (username_domain.Length == 2)
			{
				return (username_domain[0], username_domain[1], username_password[1]);
			}

			username_domain = username_password[0].Split('@');
			if (username_domain.Length == 2)
			{
				return (username_domain[1], username_domain[0], username_password[1]);
			}

			if (username_domain.Length == 1)
			{
				return (null, username_password[0], username_password[1]);
			}

			return null;
		}
	}
}
