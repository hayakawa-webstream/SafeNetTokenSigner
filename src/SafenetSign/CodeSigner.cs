﻿using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using SafenetSign.Native;

namespace SafenetSign
{
    public static class CodeSigner
    {
        public static void SignFile(string certificateThumbprint, string pin, string containerName,
            CertificateStore store, string path, string timestampUrl, SignMode mode, string dllPath, Logger logger, string timestampAlgorithmOid = null)
        {
            logger.WriteLine("Validating certificate thumbprint", true);
            if (certificateThumbprint?.Length != 40 || !ValidateThumbprint(certificateThumbprint))
            {
                throw new SigningException(
                    $"Invalid certificate thumbprint provided: {certificateThumbprint}. The thumbprint must be a valid SHA1 thumbprint - 40 characters long and consisting of only hexadecimal characters (0-9 and A-F)");
            }

            logger.WriteLine("Converting thumbprint to bytes", true);
            var binaryHash = StringToByteArray(certificateThumbprint);

            var cryptoProvider = AcquireContext(containerName, Constants.CryptoProviderName, logger);
            try
            {
                SetPin(cryptoProvider, pin, logger);

                var certStore = OpenCertificateStore(store, logger);
                try
                {
                    var certificate = RetrieveCertificate(binaryHash, certStore, out var hashHandle, out var hashBlobHandle, logger);

                    try
                    {
                        SignFile(certificate, path, timestampUrl, mode, containerName, dllPath, logger, timestampAlgorithmOid);
                    }
                    finally
                    {
                        hashHandle?.Free();
                        hashBlobHandle?.Free();
                        NativeMethods.CertFreeCertificateContext(certificate);
                    }
                }
                finally
                {
                    NativeMethods.CertCloseStore(certStore, 0);
                }
            }
            finally
            {
                NativeMethods.CryptReleaseContext(cryptoProvider, 0);
            }
        }

        private static IntPtr OpenCertificateStore(CertificateStore store, Logger logger)
        {
            var systemStore = GetSystemStore(store);

            logger.WriteLine($"Opening system-level cryptographic store {systemStore}/{Constants.CryptoStoreName}", true);
            var certStore = NativeMethods.CertOpenStore(new IntPtr(Constants.CERT_STORE_PROV_SYSTEM),
                Constants.DONT_CARE, IntPtr.Zero, systemStore, Constants.CryptoStoreName);

            if (certStore == IntPtr.Zero)
            {
                var errorResult = Marshal.GetHRForLastWin32Error();
                throw new SigningException($"Win32 error in CertOpenStore: {errorResult}",
                    Marshal.GetExceptionForHR(errorResult));
            }

            return certStore;
        }

        private static uint GetSystemStore(CertificateStore store)
        {
            uint storeToUse;
            switch (store)
            {
                case CertificateStore.User:
                    storeToUse = Constants.CERT_SYSTEM_STORE_CURRENT_USER;
                    break;
                case CertificateStore.Machine:
                    storeToUse = Constants.CERT_SYSTEM_STORE_LOCAL_MACHINE;
                    break;
                default:
                    throw new SigningException($"Unknown {nameof(CertificateStore)} value encountered: {store}");
            }

            return storeToUse;
        }

        private static bool ValidateThumbprint(string certificateThumbprint)
        {
            return Regex.IsMatch(certificateThumbprint, "[0-9A-Fa-f]{40}");
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private static IntPtr RetrieveCertificate(byte[] binaryHash, IntPtr certStore, out GCHandle? hashHandle, out GCHandle? hashBlobHandle, Logger logger)
        {
            logger.WriteLine("Retrieving certificate from the store", true);
            hashHandle = GCHandle.Alloc(binaryHash, GCHandleType.Pinned);

            var blob = new CRYPTOAPI_BLOB { cbData = binaryHash.Length, pbData = hashHandle.Value.AddrOfPinnedObject() };
            hashBlobHandle = GCHandle.Alloc(blob, GCHandleType.Pinned);

            var certificate = NativeMethods.CertFindCertificateInStore(certStore, Constants.MY_ENCODING_TYPE,
                Constants.DONT_CARE,
                Constants.CERT_FIND_SHA1_HASH, hashBlobHandle.Value.AddrOfPinnedObject(), IntPtr.Zero);

            if (certificate == IntPtr.Zero)
            {
                var errorResult = Marshal.GetHRForLastWin32Error();
                throw new SigningException($"Win32 error in CertFindCertificateInStore: {errorResult}", Marshal.GetExceptionForHR(errorResult));
            }

            return certificate;
        }

        private static void SignFile(IntPtr certificate, string path, string timestampUrl, SignMode type, string containerName, string dllPath, Logger logger, string timestampAlgorithmOid)
        {
            logger.WriteLine("Beginning the signing process", true);
            var subjectInfo = GetSubjectInfoPointer(path);
            var signerCertificate = GetSignerCertificatePointer(certificate);
            var provider = GetProviderPointer(containerName);
            var signerSignEx2Params = GetSignerSignEx2ParametersPointer(timestampUrl, type, subjectInfo, signerCertificate, provider, out var signerSignHandle, timestampAlgorithmOid);

            try
            {
                IntPtr signModule;
                if (string.IsNullOrEmpty(dllPath))
                {
                    logger.WriteLine("Loading MSSign32.dll from default path", true);
                    signModule = NativeMethods.LoadLibraryEx("MSSign32.dll", IntPtr.Zero, LoadLibraryFlags.LOAD_LIBRARY_SEARCH_SYSTEM32);
                }
                else
                {
                    logger.WriteLine($"Loading MSSign32.dll from specific path: {dllPath}", true);
                    signModule = NativeMethods.LoadLibraryEx(dllPath, IntPtr.Zero, LoadLibraryFlags.LOAD_WITH_ALTERED_SEARCH_PATH);
                }

                if (signModule == IntPtr.Zero)
                {
                    var errorResult = Marshal.GetHRForLastWin32Error();
                    throw new SigningException($"Win32 error in LoadLibraryEx: {errorResult}", Marshal.GetExceptionForHR(errorResult));
                }

                logger.WriteLine("Getting SignerSignEx2 pointer", true);
                var signerSignEx2Pointer = NativeMethods.GetProcAddress(signModule, "SignerSignEx2");

                if (signModule == IntPtr.Zero)
                {
                    var errorResult = Marshal.GetHRForLastWin32Error();
                    throw new SigningException($"Win32 error in GetProcAddress: {errorResult}", Marshal.GetExceptionForHR(errorResult));
                }

                NativeMethods.SignerSignEx2Delegate signerSignEx2;

                try
                {
                    logger.WriteLine("Marshalling SignerSignEx2 pointer to a delegate", true);
                    signerSignEx2 = Marshal.GetDelegateForFunctionPointer<NativeMethods.SignerSignEx2Delegate>(
                        signerSignEx2Pointer);
                }
                catch (Exception e)
                {
                    throw new SigningException("Error while marshalling SignerSignEx2 pointer to a managed delegate.", e);
                }

                logger.WriteLine("Invoking SignerSignEx2", true);
                var result = signerSignEx2(signerSignEx2Params.dwFlags, signerSignEx2Params.pSubjectInfo,
                    signerSignEx2Params.pSigningCert,
                    signerSignEx2Params.pSignatureInfo,
                    signerSignEx2Params.pProviderInfo,
                    signerSignEx2Params.dwTimestampFlags,
                    signerSignEx2Params.pszAlgorithmOid,
                    signerSignEx2Params.pwszTimestampURL,
                    signerSignEx2Params.pCryptAttrs,
                    signerSignEx2Params.pSipData,
                    signerSignEx2Params.pSignerContext,
                    signerSignEx2Params.pCryptoPolicy,
                    signerSignEx2Params.pReserved);

                Marshal.FreeHGlobal(signerSignEx2Params.pwszTimestampURL);
                Marshal.FreeHGlobal(signerSignEx2Params.pszAlgorithmOid);
                if (type == SignMode.APPX)
                {
                    var sipData = Marshal.PtrToStructure<APPX_SIP_CLIENT_DATA>(signerSignEx2Params.pSipData);
                    if (sipData.pAppxSipState != IntPtr.Zero)
                    {
                        Marshal.Release(sipData.pAppxSipState);
                    }
                }

                if (result != 0)
                {
                    throw new SigningException("Win32 error in SignerSignEx2:", Marshal.GetExceptionForHR(result));
                }

                logger.WriteLine("DONE", true);
            }
            finally
            {
                signerSignHandle?.Free();
            }
        }

        private static IntPtr GetProviderPointer(string containerName)
        {
            var providerInfo = new SIGNER_PROVIDER_INFO
            {
                cbSize = (uint) Marshal.SizeOf<SIGNER_PROVIDER_INFO>(),
                pwszProviderName = Marshal.StringToHGlobalUni(Constants.CryptoProviderName),
                dwProviderType = Constants.PROV_RSA_FULL,
                dwPvkChoice = Constants.PVK_TYPE_KEYCONTAINER,
                PvkChoice = new SIGNER_PROVIDER_INFO.PvkChoiceUnion
                {
                    pwszKeyContainer = Marshal.StringToHGlobalUni(containerName)
                }
            };

            var providerHandle = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_PROVIDER_INFO>());
            Marshal.StructureToPtr(providerInfo, providerHandle, false);

            return providerHandle;
        }

        private static SIGNER_SIGN_EX2_PARAMS GetSignerSignEx2ParametersPointer(string timestampUrl, SignMode type,
            IntPtr subjectInfo, IntPtr signerCertificate, IntPtr provider, out GCHandle? signerSignHandle, string timestampAlgorithmOid)
        {
            // signature info
            var signatureInfo = new SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>(),
                algidHash = Constants.CALG_SHA_256,
                dwAttrChoice = Constants.DONT_CARE,
                pAttrAuthCode = IntPtr.Zero,
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero,
            };

            var signatureHandle = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_SIGNATURE_INFO>());
            Marshal.StructureToPtr(signatureInfo, signatureHandle, false);

            // signer sign ex params
            var signerSignEx2Params = new SIGNER_SIGN_EX2_PARAMS
            {
                dwFlags = Constants.DONT_CARE,
                pSubjectInfo = subjectInfo,
                pSigningCert = signerCertificate,
                pSignatureInfo = signatureHandle,
                pProviderInfo = provider,
            };
            if (!string.IsNullOrEmpty(timestampUrl))
            {
                signerSignEx2Params.pwszTimestampURL = Marshal.StringToHGlobalUni(timestampUrl);
                if (string.IsNullOrEmpty(timestampAlgorithmOid))
                {
                    signerSignEx2Params.dwTimestampFlags = Constants.SIGNER_TIMESTAMP_AUTHENTICODE;
                }
                else
                {
                    signerSignEx2Params.dwTimestampFlags = Constants.SIGNER_TIMESTAMP_RFC3161;
                    signerSignEx2Params.pszAlgorithmOid = Marshal.StringToHGlobalAnsi(timestampAlgorithmOid);
                }
            }

            signerSignHandle = null;
            if (type == SignMode.APPX)
            {
                var sipData = new APPX_SIP_CLIENT_DATA();
                signerSignHandle = GCHandle.Alloc(signerSignEx2Params, GCHandleType.Pinned);

                sipData.pSignerParams = signerSignHandle.Value.AddrOfPinnedObject();

                var sipHandle = Marshal.AllocHGlobal(Marshal.SizeOf<APPX_SIP_CLIENT_DATA>());
                Marshal.StructureToPtr(sipData, sipHandle, false);

                signerSignEx2Params.pSipData = sipHandle;
            }

            return signerSignEx2Params;
        }

        private static IntPtr GetSignerCertificatePointer(IntPtr certificate)
        {
            // cert store info
            var certStoreInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>(),
                dwCertPolicy = Constants.SIGNER_CERT_POLICY_CHAIN_NO_ROOT,
                pSigningCert = certificate,
                hCertStore = IntPtr.Zero
            };

            // signer cert info
            var signerCertInfo = new SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>(),
                dwCertChoice = Constants.SIGNER_CERT_STORE,
                SignerCertSource = new SIGNER_CERT.SignerCertSourceUnion
                { pCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_CERT_STORE_INFO>()) }
            };

            var certHandle = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_CERT>());
            Marshal.StructureToPtr(signerCertInfo, certHandle, false);

            Marshal.StructureToPtr(certStoreInfo, signerCertInfo.SignerCertSource.pCertStoreInfo, false);
            return certHandle;
        }

        private static IntPtr GetSubjectInfoPointer(string path)
        {
            // target file info
            var signerFileInfo = new SIGNER_FILE_INFO
            {
                pwszFileName = Marshal.StringToHGlobalUni(path),
                cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>(),
                hFile = IntPtr.Zero
            };

            // subject info
            var signerSubjectInfo = new SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>(),
                pdwIndex = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(uint))),
                dwSubjectChoice = Constants.SIGNER_SUBJECT_FILE,
                SubjectChoice = new SIGNER_SUBJECT_INFO.SubjectChoiceUnion
                { pSignerFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_FILE_INFO>()) }
            };

            Marshal.StructureToPtr(Constants.DONT_CARE, signerSubjectInfo.pdwIndex, false);
            Marshal.StructureToPtr(signerFileInfo, signerSubjectInfo.SubjectChoice.pSignerFileInfo, false);

            var subjectHandle = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_SUBJECT_INFO>());
            Marshal.StructureToPtr(signerSubjectInfo, subjectHandle, false);
            return subjectHandle;
        }

        private static IntPtr AcquireContext(string containerName, string providerName, Logger logger)
        {
            var cryptoProvider = new IntPtr();

            logger.WriteLine("Acquiring cryptographic context", true);
            if (!NativeMethods.CryptAcquireContext(ref cryptoProvider, containerName,
                providerName, Constants.PROV_RSA_FULL, Constants.CRYPT_SILENT))
            {
                var errorResult = Marshal.GetHRForLastWin32Error();
                throw new SigningException($"Win32 error in CryptAcquireContext: {errorResult}", Marshal.GetExceptionForHR(errorResult));
            }

            return cryptoProvider;
        }

        private static void SetPin(IntPtr providerHandle, string tokenPin, Logger logger)
        {
            logger.WriteLine("Setting PIN", true);
            if (!NativeMethods.CryptSetProvParam(providerHandle, Constants.PP_SIGNATURE_PIN,
                System.Text.Encoding.UTF8.GetBytes(tokenPin), Constants.DONT_CARE))
            {
                var errorResult = Marshal.GetHRForLastWin32Error();
                throw new SigningException($"Win32 error in CryptSetProvParam: {errorResult}", Marshal.GetExceptionForHR(errorResult));
            }
        }
    }
}
