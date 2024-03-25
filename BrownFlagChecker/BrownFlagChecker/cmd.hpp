#pragma once

// Prevent the compiler from raising "divide by zero" error by not making it a const
int zero = 0;

#define NANOMITE_CODE_INPUT 1
#define NANOMITE_CODE_CORRECT 2
#define NANOMITE_CODE_WRONG 3
#define NANOMITE_CODE_ENCRYPT 69
#define NANOMITE_CODE_DECRYPT 96

#define NANOMITE_CMD_INPUT() zero = NANOMITE_CODE_INPUT / zero
#define NANOMITE_CMD_CORRECT() zero = NANOMITE_CODE_CORRECT / zero
#define NANOMITE_CMD_WRONG() zero = NANOMITE_CODE_WRONG / zero
#define NANOMITE_CMD_ENCRYPT() zero = NANOMITE_CODE_ENCRYPT / zero
#define NANOMITE_CMD_DECRYPT() zero = NANOMITE_CODE_DECRYPT/zero
