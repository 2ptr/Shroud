#include "common.h"

BYTE BruteDecryption(IN BYTE bFirstByte, IN PBYTE pEncrypted, IN SIZE_T sEncrypted, OUT PBYTE* pDecrypted)
{
	BYTE test = 0;
	INT i = 0;
	PBYTE pDecBuffer = (PBYTE)malloc(sEncrypted);

	while(TRUE){
		if (((pEncrypted[0] ^ test) - i) == bFirstByte)
			break;
		else
			test++;
	}

	for (int i = 0; i < sEncrypted; i++)
	{
		pDecBuffer[i] = (BYTE)((pEncrypted[i] ^ test));
	}

	*pDecrypted = pDecBuffer;
}

BOOL RC4Encrypt(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
		Data = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
	SystemFunction032(&Data, &Key);

	return TRUE;
}