#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

int k;
int tmp;
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

uint32_t key[8] = {0, 0, 0, 0, 0, 0, 0, 0};

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

uint64_t imito (char* ptr, long int size){
	uint64_t imito = 0;
	long int limit, j;
	int i;
	uint64_t tmp_block;
	uint64_t key_1, key_2;
	uint64_t block;
	
	j = 0;
	limit = size;
	while (limit > 8){
		block = ((uint64_t)(ptr[j])<<56) + ((uint64_t)(ptr[j+1])<<48) + ((uint64_t)(ptr[j+2])<<40) + ((uint64_t)(ptr[j+3])<<32) + 
				((uint64_t)(ptr[j+4])<<24) + ((uint64_t)(ptr[j+5])<<16) + ((uint64_t)(ptr[j+6])<<8) + (uint64_t)(ptr[j+7]);
		j += 8;
		imito ^= block;
		k = 0;
		for (i = 0; i < 31; i++) imito = encrypt(imito);
		imito = (imito & 0xffffffff) + ((encrypt(imito) & 0xffffffff)<<32);
		limit -= 8;
	}
	tmp_block = 0;
	k = 0;
	for (i = 0; i < 31; i++) tmp_block = encrypt(tmp_block);
	tmp_block = (tmp_block & 0xffffffff) + ((encrypt(tmp_block) & 0xffffffff)<<32);
	key_1 = (tmp_block>>63)? ((tmp_block<<1)^27) : tmp_block<<1;
	key_2 = (key_1>>63)? ((key_1<<1)^27) : key_1<<1;

	if (limit == 8) imito ^= key_1;
	else imito ^= key_2;

	block = 0;
	while (limit >=0) {
		block += ((uint64_t)(ptr[size-1-limit])<<(limit*8)); 
		limit -= 1;
	}
	imito ^= block;

	k = 0;
	for (i = 0; i < 31; i++) imito = encrypt(imito);
	imito = (imito & 0xffffffff) + ((encrypt(imito) & 0xffffffff)<<32);
	imito = imito >> 32;

	return(imito);
}

int scanner (char *directory){
	struct dirent **namelist;
	int n, i;
	int fd;
	struct stat st;
	char *name;
	int len1, len2;
	char* ptr;
	uint64_t imit;

	n = scandir(directory, &namelist, NULL, alphasort);
	if (n < 0) perror("scandir");
	else {				
		for (i = 0; i < n; i++){
			if ((strcmp(namelist[i]->d_name, "..") == 0) | (strcmp(namelist[i]->d_name, ".") == 0)) continue;
			len1 = strlen(directory);
			len2 = strlen(namelist[i]->d_name);	
			name = (char*)malloc(len1+len2+1);
			memcpy(name, directory, len1);
			memcpy(name + len1, namelist[i]->d_name, len2+1);

			if ((fd = open(name, O_RDWR)) != -1){
				if (fstat(fd, &st) == -1) printf("fstat error\n");
				if ((st.st_mode & S_IFMT) == S_IFLNK) continue;
				if ((ptr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) printf("mmap failed\n");
				imit = imito(ptr, st.st_size);
				printf("%lx name: %s\n", imit, namelist[i]->d_name);
				munmap(ptr, st.st_size);
				close(fd);
			}
			else{
				name = (char*)realloc(name, len1 + len2 + 2);
				name[len1 + len2] = '/';
				name[len1 + len2 + 1] = '\0';
				if ((fd = open(name, O_DIRECTORY)) != -1) {
					scanner(name);
					close(fd);
				}
				else printf("can't open %s file\n", namelist[i]->d_name);
			}
			free(name);
			free(namelist[i]);
		}
	}
	free(namelist);
	return(0);
}

int main(int argc, char** argv){
	
	if(argc == 2) scanner(argv[1]);
	else printf("wrong amount of parametrs");

	return(0);
}
