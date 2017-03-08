#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;

  for (i = 0; i < argc; i++)
    printf ("%s ", argv[i]);
  printf ("I will never understand.");
  printf ("\n");
  return EXIT_SUCCESS;
}
