# Launch the program : 

They're 3 versions of the code : 

## Sequential :

Do not need mpicc compiler to run launch with 

```sh
$  LD_LIBRARY_PATH=./yhash ./Base sha256 [number of threads ] ../passwords.txt hash
```

## MPI versions :

Need mpicc compiler

```sh
$  LD_LIBRARY_PATH=./yhash mpirun -np [number of process] ./MPI1 sha256 [number of threads ] ../passwords.txt hash
```

```sh
$  LD_LIBRARY_PATH=./yhash mpirun -np [number of process] ./MPI2 sha256 [number of threads ] ../passwords.txt hash
```