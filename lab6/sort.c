void sort(long *numbers, int n) {
    int i, j;
    long temp;

    for (i = 1; i < n; i++) {
        temp = numbers[i];
        j = i - 1;
        while (j >= 0 && numbers[j] > temp) {
            numbers[j + 1] = numbers[j];
            j--;
        }
        numbers[j + 1] = temp;
    }
}