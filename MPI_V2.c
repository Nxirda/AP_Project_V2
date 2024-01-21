//
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <immintrin.h>
#include <x86intrin.h>
#include <stdbool.h>

#include <unistd.h>
#include <mpi.h>

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

  " _   _      _   _           _      ____                _              \n"
  "| \\ | |_  _| | | | __ _ ___| |__  / ___|_ __ __ _  ___| | __         \n"
  "|  \\| \\ \\/ / |_| |/ _` / __| '_ \\| |   | '__/ _` |/ __| |/ /      \n"
  "| |\\  |>  <|  _  | (_| \\__ \\ | | | |___| | | (_| | (__|   <        \n"
  "|_| \\_/_/\\_\\_| |_|\\__,_|___/_| |_|\\____|_|  \\__,_|\\___|_|\\_\\ \n"
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
      d->list[i] = aligned_alloc(32, sizeof(ascii) * max_len);//malloc(sizeof(ascii) * max_len);
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
size_t load_dictionary(ascii *fd, dictionary_t *d, size_t block_size, size_t file_size)
{
  u64 i = 0;
  size_t index = 0;
  f64 elapsed = 0.0;
  f64 after   = 0.0;
  f64 before  = 0.0;
  
  if (fd)
  {
    fflush(stdout);
    before = omp_get_wtime();
    while (i < d->max_n && index < block_size && index < file_size)  
    {
	
      //Custom strlen function to take care of special separators
      size_t size = str_len((char *)fd + index);

      //For whatever reason have to check that, '\v' is on two lines so move two
      if(*(fd + index) == '\v')
      {
        index += 2;
      }
      else if(size > 0)
      {
        //Copy current password 
        strncpy(d->list[i], fd + index, size);

        d->size += size;
        index += size;     
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
    //printf("Loading dictionary block");
    printf("Loading dictionary block (%llu MiB) in %.3lf s - %.3lf GiB/s\n", d->size >> 20, elapsed, bw);
  }
  
  return index;
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
u8 compare_avx2(const u8 *restrict hash1, const u8 *restrict hash2)
{
  __m256i H1 = _mm256_load_si256((__m256i *) hash1); 
  __m256i H2 = _mm256_load_si256((__m256i *) hash2);  

  __m256i res = _mm256_xor_si256(H1, H2);

  return _mm256_testz_si256(res, res);
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
#define DICTIONNARY_SIZE 100000000

//
void handler(const char* filename, void(*hash_function)(const u8 *, const u64, u8 *), u64 nt, u64 hash_len, ascii *password, u8 *target_hash, i32 rank, i32 size)
{
    //Variables declaration
    u64 rounds   = 0;

    f64 lu_after   = 0.0;
    f64 lu_before  = 0.0;
    f64 all_after  = 0.0;
    f64 all_before = 0.0;

    //Open file with MPI
    MPI_File mpi_file;
    i32 status = MPI_File_open(MPI_COMM_WORLD, filename, MPI_MODE_RDONLY, MPI_INFO_NULL, &mpi_file);
    if(status != MPI_SUCCESS)
    {
      perror("Couldn't open file");
      MPI_Abort(MPI_COMM_WORLD, 1);
      exit(1);
    }

    //Determine file infos
    MPI_Offset file_size;
    if(rank == 0)
    {
      MPI_File_get_size(mpi_file, &file_size);
    }
    MPI_Bcast(&file_size, 1, MPI_OFFSET, 0, MPI_COMM_WORLD);
	
    //To only print once
    if(rank == 0)
    	printf("Dictionary file size: %llu MiB; %llu GiB\n\n", file_size >> 20, file_size >> 30);
	
    //Compute the chunk size for each process
    MPI_Offset chunk_size = (file_size + size -1) / size;
    MPI_Offset offset = rank * chunk_size;

    //Align offset and chunk to page size for mmap (not necessary i think for malloc)
    off_t page_size = sysconf(_SC_PAGE_SIZE);    
    chunk_size = (chunk_size / page_size) * page_size;
    offset = (offset /page_size)* page_size;

    // Create a file view for each MPI process
    MPI_File_set_view(mpi_file, offset, MPI_CHAR, MPI_CHAR, "native", MPI_INFO_NULL);

    //Mapping chunk of the file to page
    ascii *file_data = (ascii *)malloc(chunk_size +1);
    if(file_data == NULL)
    {
      perror("Couldn't allocate chunk memory");
      MPI_Abort(MPI_COMM_WORLD, 1);
      exit(1);
    }

    MPI_File_read_at_all(mpi_file, offset, file_data, chunk_size, MPI_CHAR, MPI_STATUS_IGNORE);
    MPI_File_close(&mpi_file);

    //Get L1 data cache line size for the size of the elem of the dictionnary
    off_t l1_dcache_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (l1_dcache_size <= 0) 
    {
    	perror("Error: unable to determine cache line size");
       	exit(1);
    }
	
    //Compute entry size to be aligned on cache line 
    off_t dictionnary_entry_size = l1_dcache_size / sizeof(ascii);
    all_before = omp_get_wtime();

    dictionary_t *d = create_dictionary(DICTIONNARY_SIZE, dictionnary_entry_size);

    load_dictionary(file_data, d, chunk_size, file_size); 

    lu_before = omp_get_wtime();

    u8 local_found = lookup_hash_parallel(nt, d, target_hash, hash_function, hash_len, &password);
    
    lu_after = omp_get_wtime();
    
    f64 lu_elapsed = (lu_after - lu_before);

    f64 bw = ((f64)d->size) / (lu_elapsed * 1e9);
    
    printf("Hashed and compared %llu passwords (%llu MiB), in %.3lf seconds; %.3lf GiB/s\n\n", d->n, d->size >> 20, lu_elapsed, bw);
   
    all_after = omp_get_wtime();

    f64 all_elapsed = (all_after - all_before);

    //Print and end-up all processes
    if(local_found)
    {   
	fflush(stdout);
        printf("### Cracked :]  password: '%s'\n\n", password);
        printf("Cracking run time: %.3lf seconds, %.3lf minutes; Number of rounds: %llu; Searched memory: ", all_elapsed, all_elapsed / 60.0, rounds);

        if ((size >> 20) > 1024)
          printf("%.3lf GiB\n", (f64)d->size / (1024 * 1024 *1024));
        else
          printf("%.3lf MiB\n", (f64)d->size / (1024 * 1024));

        MPI_Abort(MPI_COMM_WORLD, 0);
    }
    
    destroy_dictionary(d);
    free(d);
    munmap(file_data, file_size);
    free(file_data);
    //close(fd);

    return;
}

//
int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    //Handle command line parameters
    if (argc < 4)
    {
        MPI_Finalize();
        return printf("Usage: %s [hashing algorithm] [number of threads] [dictionary path] [hash]\n", argv[0]), 1;

    }

    //Set hash length and hash function pointer
    u64 hash_len = 0;
    void (*hash_function)(const u8 *, const u64, u8 *) = NULL;;
  
    if (!strcmp(argv[1], "md5"))
    {
        hash_len = MD5_HASH_SIZE;
        hash_function = md5hash;
    }
    else if (!strcmp(argv[1], "sha1"))
    {
	    hash_len = SHA1_HASH_SIZE;
	    hash_function = sha1hash;
    }
    else    if (!strcmp(argv[1], "sha224"))
	{
	    hash_len = SHA224_HASH_SIZE;
	    hash_function = sha224hash;
	}
    else if (!strcmp(argv[1], "sha256"))
	{
	    hash_len = SHA256_HASH_SIZE;
	    hash_function = sha256hash;
	}
	else if (!strcmp(argv[1], "sha512"))
	{
	    hash_len = SHA512_HASH_SIZE;
	    hash_function = sha512hash;
	}
	else
	{
	    printf("Error: unknown hashing algorithm '%s'\n", argv[1]);
        MPI_Finalize();
	    exit(8);
	}
  
    //Get number of threads
    u64 nt = atoll(argv[2]);
  
    if (nt < 1)
    {
        MPI_Finalize();
        return printf("Error: invalid number of threads '%llu'\n", nt), 4;

    }


    //Printing info
    if(rank == 0)
    {
        //Print logo
        printf("%s\n", yhashcrack_logo);   
        printf("Number of threads   : %llu\n"
                "Hashing algorithm   : %s\n"
                "Target hash         : %s\n"
                "Dictionary file     : %s\n", nt, argv[1], argv[4], argv[3]);
    }

    ascii *password = NULL;

    u8 target_hash[hash_len];
    str_to_hash(argv[4], target_hash, strlen(argv[4]));

    handler(argv[3], hash_function, nt, hash_len, password, target_hash, rank, size);
	
    MPI_Barrier(MPI_COMM_WORLD);
    if(password == NULL)
    {
        printf("### Sorry! No password matched the given %s hash\n\n", argv[4]);
	MPI_Abort(MPI_COMM_WORLD, 0);
    }

    free(password);

    //Quit MPI
    MPI_Finalize();
  
    return 0;
}



