//
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <immintrin.h>
#include <x86intrin.h>
#include <stdbool.h>

#include <unistd.h>

//
#include "types.h"

//
#include "yhash/yhash.h"

//
typedef struct dictionary_s {

  //List of passwords
  ascii **list;

  //Number of entries
  u64 n;

  //
  u64 max_n;

  //
  u64 size;

  //
  u64 rounds;
  
} dictionary_t;

//
typedef struct thread_task_s {

  //Pointer to the thread block of the dictionary
  ascii **list;

  //Number of passwords in the block
  u64 n;
  
  //Thread ID
  pthread_t tid;

  //The hash to crack
  u8 *target_hash;
  
  //The hash length
  u64 hash_len;
  
  //The hash function
  void (*hash_function)(const u8 *, const u64, u8 *);
  
  //
  u8 found;
  
  //The password (if found)
  ascii *password;

} thread_task_t;

//
size_t str_len(const char* buffer) {
    size_t length = 0;

    // Iterate through the characters until a newline strange char is found
    while (buffer[length] != 11 && buffer[length] != '\n' && buffer[length] != '\0' && buffer[length] != '\r' /*&& buffer[length] != ' '*/ &&buffer[length] != '\t') {
        length++;
    }

    return length;
}

//
ascii yhashcrack_logo[] =

  "     _____         _   _____             _   \n"
  " _ _|  |  |___ ___| |_|     |___ ___ ___| |_ \n"
  "| | |     | .'|_ -|   |   --|  _| .'|  _| '_|\n"
  "|_  |__|__|__,|___|_|_|_____|_| |__,|___|_,_|\n"
  "|___|                                        \n"
;

//
dictionary_t *create_dictionary(u64 max_n, u64 max_len)
{
  dictionary_t *d = malloc(sizeof(dictionary_t));
  
  if (!d)
    return printf("Error: cannot allocate dictionary\n"), NULL;
  
  d->list = malloc(sizeof(ascii *) * max_n);
  
  if (!d->list)
    return printf("Error: cannot allocate dictionary list\n"), NULL;
  
  d->n      = 0;
  d->max_n  = max_n;
  d->size   = 0;
  d->rounds = 0;
  
  for (u64 i = 0; i < max_n; i++)
    {
      d->list[i] = malloc(sizeof(ascii) * max_len);
      if (!d->list[i])
	{
	  printf("Error: cannot allocate password entry '%llu' in dictionary\n", i);
	  exit(7);
	}
    }
  
  return d;
}

//
void destroy_dictionary(dictionary_t *d)
{
  if (d)
    {
      for (u64 i = 0; i < d->max_n; i++)
	      free(d->list[i]);
      
      free(d->list);
      
      d->n      = 0;
      d->max_n  = 0;
      d->size   = 0;
      d->rounds = 0;
    }
  else
    printf("Error: dictionary pointer is NULL\n"), exit(5);
}

//
size_t load_dictionary(ascii *fd, dictionary_t *d, size_t block_size, size_t offset, size_t file_size)
{
  u64 i = 0;
  ascii done = 1;
  size_t index = offset;
  size_t last_read = 0;
  f64 elapsed = 0.0;
  f64 after   = 0.0;
  f64 before  = 0.0;
  char null_char = '\0';

  if (fd)
  {
    printf("Loading dictionary block");
    fflush(stdout);
    before = omp_get_wtime();
    while (i < d->max_n && index < offset + block_size && index < file_size)
    {
      size_t size = str_len((char *)fd + index);

      //For whatever reason have to check that, '\v' is on two lines so move two
      if(*(fd + index) == '\v')
      {
        index += 2;
      }
      else if(size > 0)
      {
        memset(d->list[i], null_char, str_len(d->list[i]));
        strncpy(d->list[i], fd + index, size);

        d->size += strlen(d->list[i]);
        index += size;     
        last_read = index;
        i++;
      }
      else
      {
        index ++;
      } 
      
    }
    after = omp_get_wtime();

    d->n = i;

    elapsed = (after - before);

    f64 bw = ((f64)d->size) / (elapsed * 1e9);
    
    printf(" (%llu MiB) in %.3lf s - %.3lf GiB/s\n", d->size >> 20, elapsed, bw);
  }
  
  if(last_read == file_size -1)
  {
    return file_size;
  }
  return last_read;
}

//Convert a string to a hash 
void str_to_hash(ascii *str, u8 *hash, u64 str_len)
{
  u8 b;
  static u8 cvt_tab[6] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
  
  for (u64 i = 0, j = 0; i < str_len; i += 2, j++)
    {
      b = 0x00;
      
      //High 4 bits
      if (str[i] >= '0' && str[i] <= '9')
	b = (str[i] - '0') << 4;
      else
	if (str[i] >= 'A' && str[i] <= 'F')
	  b = cvt_tab[str[i] - 'A'] << 4;
	else
	  if (str[i] >= 'a' && str[i] <= 'f')
	    b = cvt_tab[str[i] - 'a'] << 4;

      //Low 4 bits
      if (str[i + 1] >= '0' && str[i + 1] <= '9')
	b |= (str[i + 1] - '0') & 0x0F;
      else
	if (str[i + 1] >= 'A' && str[i + 1] <= 'F')
	  b |= cvt_tab[str[i + 1] - 'A'] & 0x0F;
	else
	  if (str[i + 1] >= 'a' && str[i + 1] <= 'f')
	    b |= cvt_tab[str[i + 1] - 'a'] & 0x0F;

      //Store byte
      hash[j] = b;
    }
}

//
void print_hash(const u8 *hash, u64 hash_len)
{
  for (u64 i = 0; i < hash_len; i++)
    printf("%02x", hash[i]);
  
  printf("\n");
}

//Optimized avx2 function for SHA256 hash (we use 256 bits register here)
//First idea was to use xor on H1 and H2 but apparently xoring does not work
u8 compare_avx2(const u8 *restrict hash1, const u8 *restrict hash2)
{
  __m256i H1 = _mm256_load_si256((__m256i *) hash1); 
  __m256i H2 = _mm256_load_si256((__m256i *) hash2);  

  __m256i res = _mm256_cmpeq_epi8(H1, H2);

  return _mm256_testc_si256(res, _mm256_set1_epi8(0xFF));
}

//
void *thread_task(void *arg)
{
  thread_task_t *tt = (thread_task_t *)arg;

  u8 found = 0;
  ascii **list = tt->list;
  u64 hash_len = tt->hash_len;

  u8 *restrict target_hash = aligned_alloc(32, hash_len * sizeof(u8));
  u8 *restrict hash        = aligned_alloc(32, hash_len * sizeof(u8));

  if(target_hash == NULL || hash == NULL)
  {
    perror("Couldn't allocate memory for hash");
    exit(1);
  } 

  target_hash = tt->target_hash; 
  
  void (*hash_function)(const u8 *, const u64, u8 *) = tt->hash_function;
  
  for (u64 i = 0; i < tt->n; i++)
  {
    hash_function((u8 *)list[i], strlen(list[i]), hash);
    
    found = compare_avx2(hash, target_hash);

    if (found)
    {
      tt->found = 1;
      tt->password = list[i];
      break;
    }
  }

  if (!found)
    tt->password = NULL;

  //free(hash);
  return NULL;
}

//
u8 lookup_hash_parallel(u64 nt, dictionary_t *d, u8 *target_hash, void (*hash_function)(const u8 *, const u64, u8 *), const u64 hash_len, ascii **password)
{
  u8 found = 0;
  u64 thread_n = d->n / nt;
  u64 thread_m = d->n % nt;
  thread_task_t *tt = malloc(sizeof(thread_task_t) * nt);
  
  if (!tt)
    {
      printf("Error: cannot allocate memory for threads\n");
      exit(6);
    }

  for (u64 i = 0; i < nt; i++)
    {
      tt[i].n = (thread_n + ((i == nt - 1) ? thread_m : 0));
      tt[i].list = &d->list[i * thread_n];
      tt[i].hash_function = hash_function;
      tt[i].target_hash = target_hash;
      tt[i].hash_len = hash_len;
      tt[i].found = 0;
      tt[i].password = NULL;

      pthread_create(&tt[i].tid, NULL, thread_task, &tt[i]);
    }

  for (u64 i = 0; i < nt; i++)
  {
    pthread_join(tt[i].tid, NULL);
    
    if (tt[i].found)
    {
      (*password) = tt[i].password;
      found = 1;
    }
  }

  free(tt);
  
  return found;
}

//
#define CHUNK_SIZE (2048 * 2048) * 32

//
void handler(const char* filename, void(*hash_function)(const u8 *, const u64, u8 *), u64 nt, u64 hash_len, ascii *password, u8 *target_hash)
{
  u8 found = 0;
  u64 size = 0;

  f64 lu_after   = 0.0;
  f64 lu_before  = 0.0;
  f64 all_after  = 0.0;
  f64 all_before = 0.0;

  //Open file
  i32 fd = open(filename, O_RDONLY);
  if(fd < 0)
  {
    perror("Couldn't open file");
    exit(1);
  }

  //Get dictionnary infos
  struct stat file_stat;
  if (stat(filename, &file_stat) < 0)
  {
    perror("Couldn't open file");
    close(fd);
    exit(1);
  }

  off_t file_size = file_stat.st_size;
  printf("Dictionary file size: %lu MiB; %lu GiB\n\n", file_size >> 20, file_size >> 30);

  //Mapping the file to page
  ascii *file_data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if(file_data == MAP_FAILED)
  {
    perror("Couldn't map file to memory");
    close(fd);
    exit(1);
  }

  //Use file chunk by chunk
  off_t offset = 0;

  dictionary_t *d = create_dictionary(CHUNK_SIZE, 32);

  all_before = omp_get_wtime();

  while(offset < file_size )
  {

    size_t remaining_size = file_size - offset;
    size_t chunk_size = (remaining_size > CHUNK_SIZE) ? CHUNK_SIZE : remaining_size;

    offset = load_dictionary(file_data, d, chunk_size, offset, file_size); 

    lu_before = omp_get_wtime();

    found = lookup_hash_parallel(nt, d, target_hash, hash_function, hash_len, &password);
      
    lu_after = omp_get_wtime();
      
    f64 lu_elapsed = (lu_after - lu_before);

    //Total searched memory size 
    size += d->size;

    f64 bw = ((f64)d->size) / (lu_elapsed * 1e9);
      
    printf("Hashed and compared %llu passwords (%llu MiB), in %.3lf seconds; %.3lf GiB/s\n\n", d->n, d->size >> 20, lu_elapsed, bw);

    if (found)
      break;
	    
    d->size = 0;
    d->rounds++;
  }  

  all_after = omp_get_wtime();

  //Printing infos
  if (found)
    printf("### Cracked :]  password: '%s'\n\n", password);
  else
    //printf("### Sorry! No password matched the given %s hash\n\n", argv[1]);
    printf("### Sorry! No password matched the given hash\n\n");

  f64 all_elapsed = (all_after - all_before);
  
  printf("Cracking run time: %.3lf seconds, %.3lf minutes; Number of rounds: %llu; Searched memory: ", all_elapsed, all_elapsed / 60.0, d->rounds);
  
  if ((size >> 20) > 1024)
    printf("%.3lf GiB\n", (f64)size / (1024 * 1024 *1024));
  else
    printf("%.3lf MiB\n", (f64)size / (1024 * 1024));
  
  munmap(file_data, file_size);
  destroy_dictionary(d);
  free(d); 
  close(fd);

  return;
}

//
int main(int argc, char **argv)
{
  //Print logo
  printf("%s\n", yhashcrack_logo);

  //Handle command line parameters
  if (argc < 4)
    return printf("Usage: %s [hashing algorithm] [number of threads] [dictionary path] [hash]\n", argv[0]), 1;

  //Set hash length and hash function pointer
  u64 hash_len = 0;
  void (*hash_function)(const u8 *, const u64, u8 *) = NULL;;
  
  if (!strcmp(argv[1], "md5"))
    {
      hash_len = MD5_HASH_SIZE;
      hash_function = md5hash;
    }
  else
    if (!strcmp(argv[1], "sha1"))
      {
	hash_len = SHA1_HASH_SIZE;
	hash_function = sha1hash;
      }
    else
      if (!strcmp(argv[1], "sha224"))
	{
	  hash_len = SHA224_HASH_SIZE;
	  hash_function = sha224hash;
	}
      else
	if (!strcmp(argv[1], "sha256"))
	  {
	    hash_len = SHA256_HASH_SIZE;
	    hash_function = sha256hash;
	  }
	else
	  if (!strcmp(argv[1], "sha512"))
	    {
	      hash_len = SHA512_HASH_SIZE;
	      hash_function = sha512hash;
	    }
	  else
	    {
	      printf("Error: unknown hashing algorithm '%s'\n", argv[1]);
	      exit(8);
	    }
  
  //Get number of threads
  u64 nt = atoll(argv[2]);
  
  if (nt < 1)
    return printf("Error: invalid number of threads '%llu'\n", nt), 4;

  //Printing info
  printf("Number of threads   : %llu\n"
	 "Hashing algorithm   : %s\n"
	 "Target hash         : %s\n"
	 "Dictionary file     : %s\n", nt, argv[1], argv[4], argv[3]);
  
  ascii *password = NULL;

  u8 target_hash[hash_len];
  str_to_hash(argv[4], target_hash, strlen(argv[4]));

  handler(argv[3], hash_function, nt, hash_len, password, target_hash);

  free(password);
  
  return 0;
}

