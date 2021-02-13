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

uint32_t CRC32(uint8_t* ptr, uint32_t len){
	uint32_t crc = (uint32_t)(~0);
	uint32_t tmp;
	int k;

	while (len--){
		crc ^= *ptr++;
		for (k = 0; k < 8; k++){
			tmp = crc >> 1;
			crc = tmp^((crc&1) ? (0xEDB88320) : 0);
		}
	}
	return crc^(uint32_t)(~0);
}

int scanner (char *directory){
	struct dirent **namelist;
	int n, i;
	int fd;
	struct stat st;
	char* ptr;
	char *name;
	int len1, len2;

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
				printf("CRC32: %x, name: %s\n", CRC32(ptr, st.st_size), name);
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
