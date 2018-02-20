//---------------------------------------------------------------------------

#ifndef aes_algoritmH
#define aes_algoritmH
//---------------------------------------------------------------------------
typedef unsigned char (pstate)[4][4];
#define Nb 4
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b} 
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// Multiplty is a macro used to multiply numbers in the field GF(2^8)
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))


void KeyExpansion(int Nk, int Nr, unsigned char * RoundKey, unsigned char * Key, int * Rcon);
void Cipher(int Nr, unsigned char * in, unsigned char * out, unsigned char * RoundKey);
void InvCipher(int Nr, unsigned char * in, unsigned char * out, unsigned char * RoundKey);

// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(28)
// Note that i starts at 1, not 0).
extern int Rcon[255]; 


#endif
