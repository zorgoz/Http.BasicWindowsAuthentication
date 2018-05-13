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

using System;
using System.Runtime.InteropServices;

namespace TaltosWorks.Owin
{
	public enum LogonType
	{
		LOGON32_LOGON_INTERACTIVE = 2,
		LOGON32_LOGON_NETWORK = 3,
		LOGON32_LOGON_BATCH = 4,
		LOGON32_LOGON_SERVICE = 5,
		LOGON32_LOGON_UNLOCK = 7,
		LOGON32_LOGON_NETWORK_CLEARTEXT = 8, // Win2K or higher
		LOGON32_LOGON_NEW_CREDENTIALS = 9 // Win2K or higher
	};

	public enum LogonProvider
	{
		LOGON32_PROVIDER_DEFAULT = 0,
		LOGON32_PROVIDER_WINNT35 = 1,
		LOGON32_PROVIDER_WINNT40 = 2,
		LOGON32_PROVIDER_WINNT50 = 3
	};

	public enum ImpersonationLevel
	{
		SecurityAnonymous = 0,
		SecurityIdentification = 1,
		SecurityImpersonation = 2,
		SecurityDelegation = 3
	}

	internal static class Win32NativeMethods
	{
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern int LogonUser(string lpszUserName,
			 string lpszDomain,
			 string lpszPassword,
			 int dwLogonType,
			 int dwLogonProvider,
			 ref IntPtr phToken);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		public static extern bool CloseHandle(IntPtr handle);
	}
}
