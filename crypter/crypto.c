#include "crypto.h"

#include <stdlib.h>
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
    char inputChar = input[i] - 'A' + 1;
    char keyChar = key.chars[i % (strlen(key.chars))] - 'A' +1;
    output[i] = ((inputChar ^ keyChar) + 'A' - 1);
   }
   return 0;
}

int encrypt(KEY key, const char* input, char* output){
  return cryptXOR(key, input, output);
}

int decrypt(KEY key, const char* cypherText, char* output){
  return cryptXOR(key, cypherText, output);
}
