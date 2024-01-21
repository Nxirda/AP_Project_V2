#Type of output and name of it
set terminal pdf
set output "Run_Time.pdf"

# Set x-axis label
set xlabel 'Hash (in hash.txt file order)'

# Set y-axis label
set ylabel 'Time in seconds'

# Set plot title
set title 'Run Time of Hash Cracking'

plot 'Run_Time_base.dat' w l title 'Base Version', \
     'Run_Time_Seq.dat' w l title 'Sequential Version', \
     'Run_Time_MPI_1.dat' w l title 'MPI First Version', \
     'Run_Time_MPI2.dat' w l title 'MPI Second Version'

pause -1 "Hit any key to continue"