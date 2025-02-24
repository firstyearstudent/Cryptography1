#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define SIZE 5

// Hàm tạo ma trận khóa
void createKeyMatrix(char key[], char keyMatrix[SIZE][SIZE]) {
    int i, j, k = 0;
    int isPresent[26] = {0}; // Mảng đánh dấu các ký tự đã xuất hiện

    // Thêm các ký tự từ khóa vào ma trận
    for (i = 0; i < strlen(key); i++) {
        if (key[i] == 'j') key[i] = 'i'; // Gộp 'i' và 'j'
        if (!isPresent[tolower(key[i]) - 'a']) {
            keyMatrix[k / SIZE][k % SIZE] = toupper(key[i]);
            isPresent[tolower(key[i]) - 'a'] = 1;
            k++;
        }
    }

    // Thêm các ký tự còn lại vào ma trận
    for (i = 0; i < 26; i++) {
        if (i != ('j' - 'a') && !isPresent[i]) {
            keyMatrix[k / SIZE][k % SIZE] = 'A' + i;
            k++;
        }
    }
}

// Hàm tìm vị trí của ký tự trong ma trận khóa
void findPosition(char keyMatrix[SIZE][SIZE], char ch, int *row, int *col) {
    if (ch == 'j') ch = 'i'; // Gộp 'i' và 'j'
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (keyMatrix[i][j] == toupper(ch)) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}

// Hàm mã hóa cặp ký tự
void encryptPair(char keyMatrix[SIZE][SIZE], char a, char b, char *cipherPair) {
    int row1, col1, row2, col2;

    findPosition(keyMatrix, a, &row1, &col1);
    findPosition(keyMatrix, b, &row2, &col2);

    if (row1 == row2) { // Cùng hàng
        cipherPair[0] = keyMatrix[row1][(col1 + 1) % SIZE];
        cipherPair[1] = keyMatrix[row2][(col2 + 1) % SIZE];
    } else if (col1 == col2) { // Cùng cột
        cipherPair[0] = keyMatrix[(row1 + 1) % SIZE][col1];
        cipherPair[1] = keyMatrix[(row2 + 1) % SIZE][col2];
    } else { // Tạo hình chữ nhật
        cipherPair[0] = keyMatrix[row1][col2];
        cipherPair[1] = keyMatrix[row2][col1];
    }
}

// Hàm chuẩn bị bản rõ (loại bỏ ký tự không phải chữ cái và thêm 'x' nếu cần)
void preparePlaintext(char plaintext[]) {
    int i, j = 0;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha(plaintext[i])) {
            plaintext[j++] = tolower(plaintext[i]);
        }
    }
    plaintext[j] = '\0'; // Kết thúc chuỗi

    // Thêm 'x' nếu độ dài bản rõ lẻ
    if (strlen(plaintext) % 2 != 0) {
        plaintext[j] = 'x';
        plaintext[j + 1] = '\0';
    }
}

// Hàm mã hóa bản rõ
void encryptPlayfair(char keyMatrix[SIZE][SIZE], char plaintext[], char ciphertext[]) {
    int i = 0;
    while (i < strlen(plaintext)) {
        char a = plaintext[i];
        char b = plaintext[i + 1];

        char cipherPair[3] = {0}; // Cặp ký tự mã hóa
        encryptPair(keyMatrix, a, b, cipherPair);
        strncat(ciphertext, cipherPair, 2); // Thêm vào bản mã
        i += 2;
    }
}

int main() {
    char key[100], plaintext[100], ciphertext[100] = "";
    char keyMatrix[SIZE][SIZE];

    // Nhập key từ bàn phím
    printf("Nhap key: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0'; // Loại bỏ ký tự xuống dòng

    // Nhập bản rõ từ bàn phím
    printf("Nhap ban ro: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0'; // Loại bỏ ký tự xuống dòng

    // Chuẩn bị bản rõ
    preparePlaintext(plaintext);

    // Tạo ma trận khóa
    createKeyMatrix(key, keyMatrix);

    // Mã hóa bản rõ
    encryptPlayfair(keyMatrix, plaintext, ciphertext);

    // In kết quả
    printf("\nMa tran khoa:\n");
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            printf("%c ", keyMatrix[i][j]);
        }
        printf("\n");
    }

    printf("\nBan ro (da chuan bi): %s\n", plaintext);
    printf("Ban ma: %s\n", ciphertext);

    return 0;
}