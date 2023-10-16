void quickSort(long *numbers, int n, int left, int right) {
    if (n != -1 ) quickSort(numbers, -1, 0, n-1);
    else{
    int i = left, j = right;
    long tmp;
    long pivot = numbers[(left + right) / 2];

    while (i <= j) {
        while (numbers[i] < pivot)
            i++;
        while (numbers[j] > pivot)
            j--;
        if (i <= j) {
            tmp = numbers[i];
            numbers[i] = numbers[j];
            numbers[j] = tmp;
            i++;
            j--;
        }
    };
 
    /* recursion */
    if (left < j)
        quickSort(numbers, -1, left, j);
    if (i < right)
        quickSort(numbers, -1, i, right);
    }
}