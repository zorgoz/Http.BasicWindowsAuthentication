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

using Owin;

namespace TaltosWorks.Owin
{
	/// <summary>
	/// Class containing extension methods for IAppBuilder
	/// </summary>
	public static class BasicWindowsAuthenticationMiddlewareExtensions
	{
		/// <summary>
		/// Extension method adding middleware 
		/// </summary>
		/// <param name="app">IAppBuilder instance to extend</param>
		/// <param name="realm">Realm to display in challenge</param>
		/// <param name="defaultDomain">Default domain to be used if no domain is specified</param>
		/// <param name="failSilently">If set to false, response header will contain failure cause. See (<see cref="BasicWindowsAuthenticationOptions">BasicWindowsAuthenticationOptions</see>)</param>
		/// <returns></returns>
		public static IAppBuilder UseBasicWindowsAuthentication(this IAppBuilder app, string realm, string defaultDomain, bool failSilently)
		{
			var options = new BasicWindowsAuthenticationOptions(realm, defaultDomain, failSilently);
			return app.UseBasicWindowsAuthentication(options);
		}

		/// <summary>
		/// Extension method adding middleware 
		/// </summary>
		/// <param name="app">IAppBuilder instance to extend</param>
		/// <param name="options">Options of type. See <see cref="BasicWindowsAuthenticationOptions">BasicWindowsAuthenticationOptions</see></param>
		/// <returns></returns>
		public static IAppBuilder UseBasicWindowsAuthentication(this IAppBuilder app, BasicWindowsAuthenticationOptions options)
		{
			return app.Use<BasicWindowsAuthenticationMiddleware>(options);
		}
	}
}
