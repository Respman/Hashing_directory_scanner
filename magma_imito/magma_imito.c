#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "test_values.h"

int k;

/* Нелинейное биективное преобразование по ГОСТ Р 34.12-2015 */
const uint8_t sbox[8][16] = {
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},   
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0}, 
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},     
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
};

//uint32_t key[8] = {0, 0, 0, 0, 0, 0, 0, 0};

void padding (uint8_t* block, int size){
	int i;
	for (i = size; i < 8; i++) block[i] = 0;
}

uint64_t encrypt (uint64_t block){
	int i;
	uint32_t right_block = (uint32_t)((block & 0xffffffff) + 
					key[(k<24) ? (k++)%8 : 31-(k++)]);
	uint64_t block_enc = (block & 0xffffffff)<<32;

	for (i = 7; i >= 0; i--) 
			block_enc += ((uint64_t)(sbox[i][(right_block & (0xf<<4*i))>>4*i])<<4*i);
	
	block_enc = (block_enc & 0xffffffff00000000) | 
				(((((uint32_t)(block_enc & 0xffffffff))>>21) | 
				 (((uint32_t)(block_enc & 0xffffffff))<<11))^ 
				((block & 0xffffffff00000000)>>32));
	
	return block_enc;
}

/*int main (){
	uint64_t blocks[4] = {0x92def06b3c130a59, 0xdb54c704f8189d20, 0x4a98fb2e67a8024c, 0x8912409b17b57e41};
	uint64_t imito = 0;
	uint64_t tmp_block;
	uint64_t key_1, key_2;
	int i, j;

	for (j = 0; j < 3; j++){
			imito ^= blocks[j];
			k = 0;
			for (i = 0; i < 31; i++) imito = encrypt(imito);
			imito = (imito & 0xffffffff) + ((encrypt(imito) & 0xffffffff)<<32);
	}			
	tmp_block = 0;
	k = 0;
	for (i = 0; i < 31; i++) tmp_block = encrypt(tmp_block);
	tmp_block = (tmp_block & 0xffffffff) + ((encrypt(tmp_block) & 0xffffffff)<<32);
	key_1 = (tmp_block>>63)? ((tmp_block<<1)^27) : tmp_block<<1;
	key_2 = (key_1>>63)? ((key_1<<1)^27) : key_1<<1;

	imito ^= blocks[3];
	imito ^= key_1;

	k = 0;
	for (i = 0; i < 31; i++) imito = encrypt(imito);
	imito = (imito & 0xffffffff) + ((encrypt(imito) & 0xffffffff)<<32);
	imito = imito >> 32;
	printf("imito = %lx\n", imito);

	return(0);
}*/

int main (int argc, char** argv){
	FILE *filein, *fileout;
	int size_block, size_next_block; 
	uint8_t *block_mas;
	uint64_t block = 0;
	uint64_t next_block;
	uint64_t tmp_block;
	uint64_t key_1, key_2;
	int i;
	if (argc == 2) {
		filein = fopen(argv[1], "rb");
		if ((size_block = fread((uint8_t*)(&block), 1, 8, filein)) != 0){
			while ((size_next_block = fread((uint8_t*)(&next_block), 1, 8, filein)) != 8){
				block_mas = (uint8_t*)(&block);
				for (i = 0; i < 4; i++){
					block_mas[i] ^= block_mas[7-i];
					block_mas[7-i] ^= block_mas[i];
					block_mas[i] ^= block_mas[7-i];
				}
				k = 0;
				for (i = 0; i < 31; i++) block = encrypt(block);
				block = (block & 0xffffffff) + ((encrypt(block) & 0xffffffff)<<32);
				block ^= next_block;
				size_block = size_next_block;
			}
			
			tmp_block = 0;
			k = 0;
			for (i = 0; i < 31; i++) tmp_block = encrypt(tmp_block);
			tmp_block = (tmp_block & 0xffffffff) + ((encrypt(tmp_block) & 0xffffffff)<<32);
			key_1 = (tmp_block>>63)? ((tmp_block<<1)^27) : tmp_block<<1;
			key_2 = (key_1>>63)? ((key_1<<1)^27) : key_1<<1;

			if (size_next_block != 0){
				block_mas = (uint8_t*)(&block);
				for (i = 0; i < 4; i++){
					block_mas[i] ^= block_mas[7-i];
					block_mas[7-i] ^= block_mas[i];
					block_mas[i] ^= block_mas[7-i];
				}
				k = 0;
				for (i = 0; i < 31; i++) block = encrypt(block);
				block = (block & 0xffffffff) + ((encrypt(block) & 0xffffffff)<<32);

				padding((uint8_t*)(&next_block), size_next_block);
				block ^= next_block;
				block ^= key_2;
				
				k = 0;
				for (i = 0; i < 31; i++) block = encrypt(block);
				block = (block & 0xffffffff) + ((encrypt(block) & 0xffffffff)<<32);
				block = (block & 0xfffe0000)>>32;
				printf("imito = %lx\n", block);
			}
			else{
				block ^= key_1;
				
				k = 0;
				for (i = 0; i < 31; i++) block = encrypt(block);
				block = (block & 0xffffffff) + ((encrypt(block) & 0xffffffff)<<32);
				block = (block & 0xfffe0000)>>32;
				printf("imito = %lx\n", block);
			}
			}
	}
	else printf("wrong amount of parametrs\n");
	return(0);
}
