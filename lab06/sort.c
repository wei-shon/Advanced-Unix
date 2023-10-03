// #include <stdio.h>
// #include <stdlib.h>

void sort_funcptr_t(long *arr , int n , int front, int end){
    if(n >=0){
        sort_funcptr_t(arr, -1,  0, n - 1);
    }
    else{
        if (front < end) {
            long pivot = arr[end];
            int i = front -1;
            for (int j = front; j < end  ; j++) {
                if (arr[j] < pivot) {
                    i++;
                    long  t = arr[i];
                    arr[i] = arr[j];
                    arr[j] = t;
                    
                }
            }
            i++;
            long t = arr[i];
            arr[i] = arr[end];
            arr[end] = t;
            sort_funcptr_t(arr, -1,  front, i - 1);
            sort_funcptr_t(arr, -1 ,  i + 1, end);
        }
    }

}

 
// void quickSort(long *arr , int n , int low, int high)
// {
//     if( n >=0 ){
//         quickSort(arr , -1 , 0 , n-1);
//     }
//     else{
//         if (low < high) {
//             long pivot = arr[high];
//             int i = (low - 1);

//             for (int j = low; j <= high - 1; j++) {
//                 if (arr[j] < pivot) {
//                     i++;
//                     long  t = arr[i];
//                     arr[i] = arr[j];
//                     arr[j] = t;
//                 }
//             }
//             long t = arr[i+1];
//             arr[i+1] = arr[high];
//             arr[high] = t;
//             quickSort(arr , -1 , low, (i+1) - 1);
//             quickSort(arr , -1 , (i+1) + 1, high);
//         }
//     }

// }

// int main(){
//     long number[8] = {2 ,4 , 10 , 6 , 3 , 14 , 20 , 17};
//     long *num = &number;
//     int n = 8;
//     (*sort_funcptr_t)(num ,n, 0 , n-1);
//     for (int i = 0 ; i < n ; i++ ){
//         printf("%ld\n" , num[i]);
//     }
// }

