1. g++ -c -fPIC calculator.cpp -o calculator.o
2. g++ -dynamiclib -o libcal.dylib calculator.o
3. g++ -c calculator.cpp -o cal.o
4. g++ -o main main.cpp -I/usr/local/openssl/include/ -L/usr/local/openssl/lib -lssl -lcrypto -L .lcal
