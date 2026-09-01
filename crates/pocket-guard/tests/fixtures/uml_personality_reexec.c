#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <sys/personality.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
    const unsigned long required = PER_LINUX | ADDR_NO_RANDOMIZE;
    char executable[4096] = { 0 };
    int previous;
    ssize_t length;

    (void)argc;
    previous = personality(required);
    if (previous < 0) {
        perror("personality");
        return 20;
    }
    if (((unsigned long)previous & required) != required) {
        length = readlink("/proc/self/exe", executable, sizeof(executable));
        if (length < 0 || (size_t)length >= sizeof(executable)) {
            perror("readlink /proc/self/exe");
            return 21;
        }
        execve(executable, argv, environ);
        perror("execve /proc/self/exe");
        return errno == 0 ? 22 : errno;
    }

    puts("POCKET_UML_PERSONALITY_OK");
    return 0;
}
