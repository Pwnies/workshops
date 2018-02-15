struct node_t {
    int v;
    struct node_t* l;
    struct node_t* r;
} node_t;

int walk(struct node_t* n, int k) {
    if (n->v > k && n->l != 0)
        return walk(n->l, k);
    if (n->r != 0)
        return walk(n->r, k);
    return n->v;
}

int check(int value) {
    struct node_t d = { .v =  42, .l = 0, .r = 0};
    struct node_t c = { .v =   1, .l = 0, .r = 0};
    struct node_t b = { .v = -10, .l = 0, .r = &d};
    struct node_t a = { .v =   0, .l = &b, .r = &c};
    return walk(&a, value) == 42;
}

int main(int argc, char* argv[]) {
    return check(*((int*)argv[1]));
}
