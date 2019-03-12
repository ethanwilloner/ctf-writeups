#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void)

{
    // Disassembly taken from ghidra and modified.

    int iVar1;
    int local_3c;
    int local_30[8];

    srand(time((time_t*)0x0));

    local_3c = 0;
    while (local_3c < 8) {
        iVar1 = rand();
        local_30[local_3c] = iVar1;
        local_3c = local_3c + 1;
    }
    int res = local_30[5] + local_30[1] + local_30[2] - local_30[3] + local_30[7] + local_30[4] - local_30[6];

    //We will subtract the result from the captcha to get the canary value

    printf("%d\n", res);

    return 0;
}
