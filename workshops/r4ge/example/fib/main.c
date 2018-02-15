
int main(int argc, char* argv[]) {
    if (argc != 2) return -1;

    char *a = argv[1];

    int ok = 1;
    ok &= (a[0] == 1);
    ok &= (a[1] == 1);
    for (int n = 2; n < 10; n++)
        ok &= (a[n] == a[n - 1] + a[n - 2]);

    if (ok) printf("fibulous\n");
}
