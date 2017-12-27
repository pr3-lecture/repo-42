#include "crypto.h"

#include <stdio.h>
#include <string.h>

/**
prüft ob ein illegales Zeichen im Key vorhanden ist
1 wenn illegales vorhanden
0 wenn kein illegales vorhanden
**/
int hasIllegalChar(const char* keyChars, const char* allowedChars) {
  int i;
  int foundIllegalChar = 1;
  for (i = 0; i < strlen(keyChars); i++) {
    int j;
    for (j = 0; j < strlen(allowedChars); j++) {
      if (keyChars[i] == allowedChars[j]) {
        foundIllegalChar = 0;
        break;
      }
    }
  }
  return foundIllegalChar;
}

int cryptXOR (KEY key,const char* input, char* output){

  if(strlen(key.chars) == 0) {
      return E_KEY_TOO_SHORT;
    }
  if (hasIllegalChar(key.chars, KEY_CHARACTERS)){
      return E_KEY_ILLEGAL_CHAR;
    }
  if (hasIllegalChar(input, MESSAGE_CHARACTERS)){
    return E_MESSAGE_ILLEGAL_CHAR;
    }

  int i;
  for(i = 0; i < strlen(input); i++) {
      output[i] = input[i] ^ key.chars[i % (sizeof(key)/sizeof(char))];
   }
   return 0;
}

int encrypt(KEY key, const char* input, char* output){
  return cryptXOR(key, input, output);
}

int decrypt(KEY key, const char* cypherText, char* output){
  return cryptXOR(key, cypherText, output);
}

int main (int argc, char *argv[]) {
	char baseStr[] = "HELLOWORLD";
  KEY.type = 1;
  KEY.chars = "TPE";

	char encrypted[strlen(baseStr)];
	encrypt(KEY, baseStr, encrypted);
	printf("Encrypted:%s\n", encrypted);

	char decrypted[strlen(baseStr)];
	encryptDecrypt(KEY,encrypted, decrypted);
	printf("Decrypted:%s\n", decrypted);
}
