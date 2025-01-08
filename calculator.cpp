#include "calculator.hpp"
#include<iostream>

float add(float a, float b) {
    return a+b;
}
float sub(float a, float b) {
    return a - b;
}
float mul(float a, float b) {
    return a*b;
}
float division(float a, float b) {
    return b != 0 ? a / b : 0;
}