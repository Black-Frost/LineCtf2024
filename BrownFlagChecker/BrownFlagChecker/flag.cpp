#include "flag.hpp"

// To make sure the ascii trick is not optimized away, these offsets should be defined as volatile global variables
volatile DWORD64 inputOffset = 0;
volatile DWORD64 tokenOffset = 0;
volatile DWORD64 keyOffset = 0;
volatile DWORD64 ivOffset = 0;

//const char* offsetArray[] = { "GUY", "ICE", "MOO", "VIM", "DOG", "CAT", "QRS", "ZIP", "BAT", "EYE", "DEF", "SPE", "WIN", "ATK", "CRY", "ABC", "RED", "AIR", "COW", "EGG" };
/* const char* usageMap[] = {
'BAT', 'COW', 
'SPE', 'EYE', 
'WIN', 'ABC', 
'CRY', 'ICE', 
'CAT', 'DOG', 
'VIM', 'ATK', 
'ZIP', 'RED', 
'DEF', 'QRS', 
'AIR', 'MOO'}*/

bool checkKey() {
	memcpy((void*)&inputOffset, "GUY", 3);
	memcpy((void*)&tokenOffset, "EGG", 3);

	char* encryptedBuffer = (char*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD64 shadowBase;
	shadowBase = openMemory();
	memcpy(encryptedBuffer, (char*)(shadowBase + (inputOffset << 12)), 4096);
	//printf("Input: %lld\n", encryptedBuffer);
	closeMemory();

	AES_ctx ctx; 

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "BAT", 3);
	memcpy((void*)&ivOffset, "COW", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "SPE", 3);
	memcpy((void*)&ivOffset, "EYE", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "WIN", 3);
	memcpy((void*)&ivOffset, "ABC", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "CRY", 3);
	memcpy((void*)&ivOffset, "ICE", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "CAT", 3);
	memcpy((void*)&ivOffset, "DOG", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "VIM", 3);
	memcpy((void*)&ivOffset, "ATK", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "ZIP", 3);
	memcpy((void*)&ivOffset, "RED", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "DEF", 3);
	memcpy((void*)&ivOffset, "QRS", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();

	shadowBase = openMemory();
	memcpy((void*)&keyOffset, "AIR", 3);
	memcpy((void*)&ivOffset, "MOO", 3);
	AES_init_ctx_iv(&ctx, (uint8_t*)(shadowBase + (keyOffset << 12)), (uint8_t*)(shadowBase + (ivOffset << 12)));
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encryptedBuffer, 64);
	closeMemory();


	shadowBase = openMemory();
	char* tokenAddr = (char*)(shadowBase + (tokenOffset << 12));
	boolean result =  memcmp(encryptedBuffer, tokenAddr, KEY_LEN) == 0;
	closeMemory();

	return result;
}

void printFlag(char* key) {
	uint8_t hash[16];
	md5String(key, hash);
	AES_ctx ctx;
	char flag[] = { 190, 242, 112, 48, 102, 161, 253, 244, 60, 143, 146, 46, 88, 219, 144, 196, 20, 92, 180, 254, 208, 172, 101, 21, 182, 10, 134, 205, 183, 51, 143, 112, 217, 223, 176, 107, 97, 39, 247, 194, 24, 107, 250, 167, 170, 23, 220, 27 };
	const char iv[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	AES_init_ctx_iv(&ctx, (const uint8_t*)hash, (const uint8_t * )iv);
	AES_CBC_decrypt_buffer(&ctx, (uint8_t*)flag, 48);
	printf("Flag: %s\n", flag);
}