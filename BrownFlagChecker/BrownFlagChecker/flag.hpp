#pragma once
#include <Windows.h>
#include "md5.hpp"
#include "aes.hpp"
#include "BrownFlagChecker.hpp"

// KEY = "H4VIn9_7Hi5_KEY_ME4n5_you_4rE_che47In9_ON_me_7f6301e1920cb86cf8e"
#define KEY_LEN 64

bool checkKey();

void printFlag(char* key);
