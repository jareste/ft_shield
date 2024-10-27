#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdint.h>
#include "ft_ssl.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	char	*str;
	size_t	i;
	size_t	c;

	if (!s1 || !s2)
		return (0);
	str = (char *)malloc(sizeof(char) * (strlen(s1) + strlen(s2) + 1));
	if (!str)
		return (0);
	i = 0;
	while (s1[i])
	{
		str[i] = s1[i];
		i++;
	}
	c = 0;
	while (s2[c])
	{
		str[i + c] = s2[c];
		c++;
	}
	str[i + c] = '\0';
	return (str);
}

void encode_and_store_in_file(const char* input_string, const char* filename) 
{
    size_t encoded_size;
    char* encoded_string = base64_encode((const uint8_t*)input_string, strlen(input_string), &encoded_size);

    FILE *file = fopen(filename, "w");
    if (!file)
	{
        free(encoded_string);
        return;
    }
    fwrite(encoded_string, sizeof(char), encoded_size, file);
	fputc('\n', file);
    fclose(file);

    free(encoded_string);
}

char* read_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = (char*)malloc(file_size + 1);

    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);

    return content;
}

int main(int argc, char *argv[]) //FUNDAMENTAL QUE LOS LOGS VENGAN CON \n QUE SINO SE CONCATENARAN SIN ESPACIOS
{  
	size_t decoded_size;
	
	char *encode_str = read_file("log.txt");
    if (!read_file)
		return (0);
	
	char *decoded_string = base64_decode((const uint8_t*)encode_str, strlen(encode_str), &decoded_size);
	//if (!decoded_string)
	//	decoded_string = strdup("");
	//DEBUG//printf("DECODE ANTES DE CONCATENAR:|%s|\n", decoded_string);	
	char *final_decode = ft_strjoin(decoded_string, argv[1]);
	//DEBUG//printf("DECODE DESPUES DE CONCATENAR:|%s|\n", final_decode);	
	free(decoded_string);
	encode_and_store_in_file(final_decode, "log.txt");
	free(final_decode);
	//DEBUF//encode_str = read_file("log.txt");
	/*DEBUGif (encode_str)
	{
		//DEBUG//printf("ENCODE STR:|%s|\n", encode_str);
		decoded_string = base64_decode((const uint8_t*)encode_str, strlen(encode_str), &decoded_size);
		//DEBUG//printf("DECODE STR:|%s|\n", decoded_string);
		free(decoded_string);
        free(encode_str);
	}FINISH DEBUG*/
    return (0);
}