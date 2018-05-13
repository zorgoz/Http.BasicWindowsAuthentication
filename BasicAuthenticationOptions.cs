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

namespace TaltosWorks.Owin
{
	/// <summary>
	/// Class incorporates authentication options for basic auth based windows authentication
	/// </summary>
	public class BasicWindowsAuthenticationOptions : AuthenticationOptions
	{
		/// <summary>
		/// Realm to be added as challenge
		/// </summary>
		public string Realm { get; }

		/// <summary>
		/// Default domain to be used when username contains no domain information
		/// </summary>
		public string DefaultDomain { get; }

		/// <summary>
		/// Should the result contain failure cause, or not. If set to false, logon failure cause is included in the http response.
		/// </summary>
		/// <remarks>The header will contain following fields: 
		/// <ul>
		/// <li>X-LogonFailureReason=reason as string</li>
		/// <li>X-LogonFailureCode=the error code set by LogonUser</li>
		/// </ul>
		/// </remarks>
		public bool FailSilently { get; }

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="realm">Realm to be added as challenge</param>
		/// <param name="defaultDomain">Default domain to be used when username contains no domain information</param>
		/// <param name="failSilently">Should the result contain failure cause</param>
		public BasicWindowsAuthenticationOptions(string realm, string defaultDomain, bool failSilently)
			: base("Basic")
		{
			Realm = realm;
			DefaultDomain = defaultDomain;
			FailSilently = failSilently;
		}
	}
}
